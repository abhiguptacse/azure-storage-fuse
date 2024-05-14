package encryptor

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Azure/azure-storage-fuse/v2/common/config"
	"github.com/Azure/azure-storage-fuse/v2/common/log"
	"github.com/Azure/azure-storage-fuse/v2/internal"
	"github.com/Azure/azure-storage-fuse/v2/internal/handlemap"
)

type Encryptor struct {
	internal.BaseComponent
	handle           *os.File
	blockSize        uint64
	mountPointCipher string
	encryptionKey    []byte
}

type LastChunkMeta struct {
	sync.Mutex
	farthestBlockSeen int64 // keep track of the farthest block that has been written to the file
	paddingLength     int64 // keep track of the padding length of the last block
}

var lastchunkMeta = &LastChunkMeta{
	farthestBlockSeen: -1,
	paddingLength:     0,
}

type EncryptorOptions struct {
	BlockSize          uint64 `config:"block-size-mb" yaml:"block-size-mb,omitempty"`
	EncryptedMountPath string `config:"encrypted-mount-path" yaml:"encrypted-mount-path,omitempty"`
	EncryptionKey      string `config:"encryption-key" yaml:"encryption-key,omitempty"`
}

const (
	compName    = "encryptor"
	AuthTagSize = 16
	NonceSize   = 12
	MetaSize    = 28
)

var _ internal.Component = &Encryptor{}

func (e *Encryptor) Name() string {
	return compName
}

func (e *Encryptor) SetName(name string) {
	e.BaseComponent.SetName(name)
}

func (e *Encryptor) SetNextComponent(nc internal.Component) {
	e.BaseComponent.SetNextComponent(nc)
}

func (e *Encryptor) Priority() internal.ComponentPriority {
	return internal.EComponentPriority.LevelMid()
}

func (e *Encryptor) Configure(isParent bool) error {
	log.Trace("Encryptor::Configure :  %s", e.Name())

	// Read the configuration
	conf := EncryptorOptions{}
	err := config.UnmarshalKey(e.Name(), &conf)
	if err != nil {
		log.Err("Encryptor::Configure : config error [invalid config attributes]")
		return fmt.Errorf("error reading config for %s: %w", e.Name(), err)
	}

	// fetch encryption key from environment variable
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		key = conf.EncryptionKey
	}

	if key == "" {
		log.Err("Encryptor::Configure : encryption key not set")
		return fmt.Errorf("encryption key not set")
	} else {
		e.encryptionKey, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Err("Encryptor::Configure : error decoding encryption key")
			return fmt.Errorf("error decoding encryption key: %w", err)
		}
	}

	e.blockSize = 1024 * 1024 // default block size is 1MB
	if config.IsSet(e.Name() + ".block-size-mb") {
		e.blockSize = conf.BlockSize * 1024 * 1024
	}

	e.mountPointCipher = "/mnt/cipher/"
	if config.IsSet(e.Name() + ".encrypted-mount-path") {
		e.mountPointCipher = conf.EncryptedMountPath
	}

	log.Info("Encryptor::Configure : block size %d, encrypted mount path %s", e.blockSize, e.mountPointCipher)
	return nil
}

func (e *Encryptor) Start(ctx context.Context) error {
	return nil
}
func (e *Encryptor) CommitData(opt internal.CommitDataOptions) error {

	defer e.handle.Close()
	lastchunkMeta.Lock()
	defer lastchunkMeta.Unlock()

	if lastchunkMeta.farthestBlockSeen != -1 {
		// Write the padding length to the end of the file
		paddingLengthByte := make([]byte, 8)
		binary.BigEndian.PutUint64(paddingLengthByte, uint64(lastchunkMeta.paddingLength))
		endoffset := (lastchunkMeta.farthestBlockSeen + 1) * (int64(e.blockSize) + MetaSize)
		n, err := e.handle.WriteAt(paddingLengthByte, endoffset)
		log.Info("Encryptor::CommitData : writing %d bytes, padding length %d at offset %d", n, lastchunkMeta.paddingLength, endoffset)
		if err != nil {
			log.Err("Encryptor: Error writing padding length to file: %s", err.Error())
			return err
		}
		lastchunkMeta.farthestBlockSeen = -1
		lastchunkMeta.paddingLength = 0
	}
	return nil
}

func (e *Encryptor) CreateFile(options internal.CreateFileOptions) (*handlemap.Handle, error) {
	// Create the file in the mount point
	log.Info("Encryptor::createFile : %s", e.mountPointCipher+options.Name)

	// Take a map of file handles for parallel read/write to different files ?
	handle := handlemap.NewHandle(options.Name)
	if handle == nil {
		log.Trace("Encryptor::createFile : Failed to create handle for file: %s", options.Name)
		return nil, syscall.EFAULT
	}
	handle.Mtime = time.Now()

	fileHandle, err := os.OpenFile(e.mountPointCipher+options.Name, os.O_RDWR|os.O_CREATE, options.Mode)
	if err != nil {
		log.Trace("Encryptor::createFile : Error creating file: %s", err.Error())
		return nil, err
	}

	e.handle = fileHandle
	// Set the file handle in the handle
	return handle, nil
}

func formatListDirName(path string) string {
	// If we check the root directory, make sure we pass "" instead of "/"
	// If we aren't checking the root directory, then we want to extend the directory name so List returns all children and does not include the path itself.
	if path == "/" {
		path = ""
	} else if path != "" {
		path = internal.ExtendDirName(path)
	}
	return path
}

func (e *Encryptor) StreamDir(options internal.StreamDirOptions) ([]*internal.ObjAttr, string, error) {
	var objAttrs []*internal.ObjAttr
	path := formatListDirName(options.Name)
	log.Info("Encryptor::StreamDir : %s", path)
	// Get a list of files in the directory
	files, err := os.ReadDir(e.mountPointCipher + path)
	if err != nil {
		log.Trace("Encryptor::StreamDir : Error reading directory %s : %s", path, err.Error())
		return nil, "", err
	}

	// Iterate through files
	for _, file := range files {
		// Call GetAttr method for each file
		attr, err := e.GetAttr(internal.GetAttrOptions{Name: path + file.Name()})
		if err != nil {
			if err != syscall.ENOENT {
				log.Trace("Encryptor::StreamDir : Error getting file attributes: %s", err.Error())
				return objAttrs, "", err
			}
			log.Trace("Encryptor::StreamDir : File not found: %s", file.Name())
			continue
		}

		// Append the result to objAttrs
		objAttrs = append(objAttrs, attr)
	}

	// Return the objAttrs list and nil error
	return objAttrs, "", nil
}

func checkForActualFileSize(fileHandle *os.File, currentFileSize int64, blockSize int64) (int64, error) {

	totalBlocks := currentFileSize / (blockSize + MetaSize)
	if currentFileSize < totalBlocks*(blockSize+MetaSize)+8 {
		return 0, nil
	}

	// Read the last 8 bytes of file and check for padding
	paddingLengthBytes := make([]byte, 8)
	_, err := fileHandle.ReadAt(paddingLengthBytes, currentFileSize-8)
	if err != nil {
		log.Err("Encryptor: Error reading last 8 bytes of file: %s", err.Error())
		return 0, err
	}

	actualFileSize := currentFileSize - int64(binary.BigEndian.Uint64(paddingLengthBytes)) - MetaSize - 8
	return actualFileSize, nil
}

func (e *Encryptor) GetAttr(options internal.GetAttrOptions) (attr *internal.ObjAttr, err error) {
	// Open the file from the mount point and get the attributes.
	log.Info("Encryptor::GetAttr for %s", options.Name)
	fileAttr, err := os.Stat(e.mountPointCipher + options.Name)
	if err != nil {
		if os.IsNotExist(err) {
			log.Trace("Encryptor::GetAttr : File not found: %s", options.Name)
			return nil, syscall.ENOENT
		}
		log.Trace("Encryptor::GetAttr : Error getting file attributes: %s", err.Error())
		return &internal.ObjAttr{}, nil
	}

	// Populate the ObjAttr struct with the file info
	attr = &internal.ObjAttr{
		Mtime:  fileAttr.ModTime(),                // Modified time
		Atime:  time.Now(),                        // Access time (current time as approximation)
		Ctime:  fileAttr.ModTime(),                // Change time (same as modified time in this case)
		Crtime: fileAttr.ModTime(),                // Creation time (not available in Go, using modified time)
		Mode:   fileAttr.Mode(),                   // Permissions
		Path:   e.mountPointCipher + options.Name, // Full path
		Name:   fileAttr.Name(),                   // Base name of the path
	}
	fileHandle, err := os.OpenFile(e.mountPointCipher+options.Name, os.O_RDONLY, 0666)
	if err != nil {
		log.Trace("Encryptor::GetAttr : Error opening file: %s", err.Error())
		return nil, err
	}
	defer fileHandle.Close()

	if fileAttr.IsDir() {
		attr.Size = fileAttr.Size()
		attr.Flags.Set(internal.PropFlagIsDir)
	} else {
		actualFileSize, err := checkForActualFileSize(fileHandle, fileAttr.Size(), int64(e.blockSize))
		if err != nil {
			log.Err("Encryptor: Error checking for actual file size: %s", err.Error())
			return nil, err
		}
		log.Debug("Encryptor::GetAttr : actual file size %d", actualFileSize)
		attr.Size = actualFileSize
	}
	return attr, nil
}

func (e *Encryptor) StageData(opt internal.StageDataOptions) error {
	log.Info("Encryptor::StageData : %s, offset %d, data %d", opt.Name, opt.Offset, len(opt.Data))
	return encryptWriteBlock(e.handle, opt.Name, opt.Data, opt.Offset, e.blockSize, e.encryptionKey)
}

func encryptWriteBlock(encryptedFile *os.File, name string, data []byte, blockId uint64, blockSize uint64, encryptionKey []byte) error {

	paddingLength := int64(0)
	if len(data) < int(blockSize) {
		// Pad the data to the block size
		paddingLength = int64(blockSize) - int64(len(data))
		data = append(data, make([]byte, paddingLength)...)
	}
	encryptedChunk, nonce, err := EncryptChunk(data, encryptionKey)
	if err != nil {
		log.Err("Encryptor: Error encrypting data: %s", err.Error())
		return err
	}

	encryptedChunkOffset := int64(blockId) * (int64(blockSize) + int64(MetaSize))
	// Write the combined nonce and encrypted chunk
	n, err := encryptedFile.WriteAt(append(nonce, encryptedChunk...), encryptedChunkOffset)
	log.Debug("Encryptor:: encryptWriteBlock: writing %d bytes to encrypted file: %s at offset %d", n, name, encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error writing encrypted chunk to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset, n)
		return err
	}

	lastchunkMeta.Lock()
	defer lastchunkMeta.Unlock()
	if int64(blockId) > lastchunkMeta.farthestBlockSeen {
		lastchunkMeta.farthestBlockSeen = int64(blockId)
	}
	lastchunkMeta.paddingLength = paddingLength
	log.Debug("Encryptor:: encryptWriteBlock: endBlockIndex %d, paddingLength %d", lastchunkMeta.farthestBlockSeen, lastchunkMeta.paddingLength)
	return nil
}

func (e *Encryptor) ReadInBuffer(options internal.ReadInBufferOptions) (length int, err error) {
	log.Trace("Encryptor::ReadInBuffer : Read %s from %d offset", options.Handle.Path, options.Offset)

	if options.Offset > atomic.LoadInt64(&options.Handle.Size) {
		return 0, syscall.ERANGE
	}

	var dataLen int64 = int64(len(options.Data))
	if atomic.LoadInt64(&options.Handle.Size) < (options.Offset + int64(len(options.Data))) {
		dataLen = options.Handle.Size - options.Offset
	}

	if dataLen == 0 {
		return 0, nil
	}

	err = readAndDecryptBlock(options.Handle.Path, options.Offset, options.Data, e.blockSize, e.encryptionKey, e.mountPointCipher)
	if err != nil {
		log.Err("Encryptor::ReadInBuffer : Failed to read %s [%s] from offset %d", options.Handle.Path, err.Error(), options.Offset)
		return 0, err
	}

	length = int(dataLen)
	return
}

func readAndDecryptBlock(name string, offset int64, data []byte, blockSize uint64, encryptionKey []byte, mountPointCipher string) error {
	log.Debug("Encryptor::ReadAndDecryptBlock : Read %s from %d offset for data size %d", name, offset, len(data))

	fileHandle, err := os.OpenFile(mountPointCipher+name, os.O_RDONLY, 0666)
	if err != nil {
		log.Err("Encryptor::ReadAndDecryptBlock : Error opening encrypted file: %s", err.Error())
		return err
	}
	defer fileHandle.Close()
	chunkIndex := offset / int64(blockSize)
	encryptedChunkOffset := chunkIndex * (int64(blockSize) + MetaSize)
	encryptedChunk := make([]byte, blockSize+MetaSize)

	n, err := fileHandle.ReadAt(encryptedChunk, encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error reading encrypted file: %s", err.Error())
		return err
	}

	log.Debug("Encryptor: Read %d bytes from encrypted file", n)

	plainText, err := DecryptChunk(encryptedChunk[NonceSize:], encryptedChunk[:NonceSize], encryptionKey)
	if err != nil {
		log.Err("Encryptor: Error decrypting file: %s", err.Error())
		return err
	}

	copy(data, plainText)
	return nil
}

func (e *Encryptor) CreateDir(options internal.CreateDirOptions) error {
	// Create the directory in the mount point
	log.Info("Encryptor::CreateDir : %s", e.mountPointCipher+options.Name)
	err := os.Mkdir(e.mountPointCipher+options.Name, 0777)
	if err != nil {
		log.Trace("Encryptor::CreateDir : Error creating directory: %s", err.Error())
		return err
	}
	return nil
}

func NewEncryptorComponent() internal.Component {
	comp := &Encryptor{}
	comp.SetName(compName)
	return comp
}

func init() {
	internal.AddComponent(compName, NewEncryptorComponent)
}
