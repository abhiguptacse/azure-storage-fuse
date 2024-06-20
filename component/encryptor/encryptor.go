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

// Implements two mount approach with only one file for data and metadata.
type Encryptor struct {
	internal.BaseComponent
	handle           *os.File
	blockSize        uint64
	mountPointCipher string
	encryptionKey    []byte
	lastChunkMeta    *LastChunkMeta
}

type LastChunkMeta struct {
	sync.Mutex
	farthestBlockSeen int64 // keep track of the farthest block that has been written to the file.
	paddingLength     int64 // keep track of the padding length of the last block.
}

type encryptorOptions struct {
	BlockSize          uint64 `config:"block-size-mb" yaml:"block-size-mb,omitempty"`
	EncryptedMountPath string `config:"encrypted-mount-path" yaml:"encrypted-mount-path,omitempty"`
	EncryptionKey      string `config:"encryption-key" yaml:"encryption-key,omitempty"`
}

const (
	compName    = "encryptor"
	AuthTagSize = 16
	NonceSize   = 12
	MetaSize    = 28 // Sum of AuthTagSize and NonceSize.
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

	conf := encryptorOptions{}
	err := config.UnmarshalKey(e.Name(), &conf)
	if err != nil {
		log.Err("Encryptor::Configure : config error [invalid config attributes]")
		return fmt.Errorf("error reading config for %s: %w", e.Name(), err)
	}

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		key = conf.EncryptionKey
		if key == "" {
			log.Err("Encryptor::Configure : encryption key not set")
			return fmt.Errorf("encryption key not set")
		}
	}

	e.encryptionKey, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Err("Encryptor::Configure : error decoding encryption key")
		return fmt.Errorf("error decoding encryption key: %w", err)
	}

	e.blockSize = 1024 * 1024 // default block size is 1MB
	if config.IsSet(e.Name()+".block-size-mb") && conf.BlockSize > 0 {
		e.blockSize = conf.BlockSize * 1024 * 1024
	}

	e.mountPointCipher = "/mnt/cipher/"
	if config.IsSet(e.Name() + ".encrypted-mount-path") {
		e.mountPointCipher = conf.EncryptedMountPath
	}

	e.lastChunkMeta = &LastChunkMeta{
		farthestBlockSeen: -1,
		paddingLength:     0,
	}

	log.Info("Encryptor::Configure : block size %d, encrypted mount path %s", e.blockSize, e.mountPointCipher)
	return nil
}

func (e *Encryptor) Start(ctx context.Context) error {
	return nil
}
func (e *Encryptor) CommitData(opt internal.CommitDataOptions) error {

	defer e.handle.Close()
	e.lastChunkMeta.Lock()
	defer e.lastChunkMeta.Unlock()

	if e.lastChunkMeta.farthestBlockSeen != -1 {
		paddingLengthByte := make([]byte, 8)
		binary.BigEndian.PutUint64(paddingLengthByte, uint64(e.lastChunkMeta.paddingLength))
		endoffset := (e.lastChunkMeta.farthestBlockSeen + 1) * (int64(e.blockSize) + MetaSize)
		n, err := e.handle.WriteAt(paddingLengthByte, endoffset)
		log.Info("Encryptor::CommitData : writing %d bytes, padding length %d at offset %d", n, e.lastChunkMeta.paddingLength, endoffset)
		if err != nil {
			log.Err("Encryptor: Error writing padding length to file: %s", err.Error())
			return err
		}
		e.lastChunkMeta.farthestBlockSeen = -1
		e.lastChunkMeta.paddingLength = 0
	}
	return nil
}

func (e *Encryptor) CreateFile(options internal.CreateFileOptions) (*handlemap.Handle, error) {
	log.Info("Encryptor::createFile : %s", e.mountPointCipher+options.Name)

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
	return handle, nil
}

func formatListDirName(path string) string {
	// If we check the root directory, make sure we pass "" instead of "/".
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
	files, err := os.ReadDir(e.mountPointCipher + path)
	if err != nil {
		log.Trace("Encryptor::StreamDir : Error reading directory %s : %s", path, err.Error())
		return nil, "", err
	}

	for _, file := range files {
		attr, err := e.GetAttr(internal.GetAttrOptions{Name: path + file.Name()})
		if err != nil {
			if err != syscall.ENOENT {
				log.Trace("Encryptor::StreamDir : Error getting file attributes: %s", err.Error())
				return objAttrs, "", err
			}
			log.Trace("Encryptor::StreamDir : File not found: %s", file.Name())
			continue
		}

		objAttrs = append(objAttrs, attr)
	}

	return objAttrs, "", nil
}

func checkForActualFileSize(fileHandle *os.File, currentFileSize int64, blockSize int64) (int64, error) {

	log.Info("Encryptor::checkForActualFileSize : currentFileSize %d", currentFileSize)
	totalBlocks := currentFileSize / (blockSize + MetaSize)
	if currentFileSize < totalBlocks*(blockSize+MetaSize)+8 {
		return 0, nil
	}

	// Read the last 8 bytes of file and check for padding length.
	paddingLengthBytes := make([]byte, 8)

	// TODO(abhinavgupta) : Find a way to block this read until the last write is done.
	// While writing to a file if there is a list operation coming in, it will read the
	// wrong padding length.
	_, err := fileHandle.ReadAt(paddingLengthBytes, currentFileSize-8)
	if err != nil {
		log.Err("Encryptor: Error reading last 8 bytes of file: %s", err.Error())
		return 0, err
	}

	actualFileSize := currentFileSize - int64(binary.BigEndian.Uint64(paddingLengthBytes)) - totalBlocks*MetaSize - 8
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
		return &internal.ObjAttr{}, err
	}

	// Populate the ObjAttr struct with the file info.
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
		attr.Size = actualFileSize
	}
	return attr, nil
}

// Encrypt the incoming block of data using the encryption key and writing it
// to the cipher mount point.
func (e *Encryptor) StageData(opt internal.StageDataOptions) error {
	log.Info("Encryptor::StageData : %s, offset %d, data %d", opt.Name, opt.Offset, len(opt.Data))

	paddingLength := int64(0)
	dataLen := int64(len(opt.Data))
	blockId := opt.Offset
	if dataLen < int64(e.blockSize) {
		// Pad the data to the block size.
		paddingLength = int64(e.blockSize) - dataLen
		opt.Data = append(opt.Data, make([]byte, paddingLength)...)
	}
	encryptedChunk, nonce, err := EncryptChunk(opt.Data, e.encryptionKey)
	if err != nil {
		log.Err("Encryptor: Error encrypting data: %s", err.Error())
		return err
	}

	encryptedChunkOffset := int64(blockId) * (int64(e.blockSize) + int64(MetaSize))
	// Write the combined nonce and encrypted chunk.
	n, err := e.handle.WriteAt(append(nonce, encryptedChunk...), encryptedChunkOffset)
	log.Debug("Encryptor::StageData : writing %d bytes to encrypted file: %s at offset %d", n, opt.Name, encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error writing encrypted chunk to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset, n)
		return err
	}

	e.lastChunkMeta.Lock()
	defer e.lastChunkMeta.Unlock()
	if int64(blockId) > e.lastChunkMeta.farthestBlockSeen {
		e.lastChunkMeta.farthestBlockSeen = int64(blockId)
	}

	e.lastChunkMeta.paddingLength = paddingLength
	log.Debug("Encryptor:: encryptWriteBlock: endBlockIndex %d, paddingLength %d", e.lastChunkMeta.farthestBlockSeen, e.lastChunkMeta.paddingLength)
	return nil
}

// Read the block of data from the cipher mount, decrypt and return the plain text buffer.
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

	name := options.Handle.Path
	log.Debug("Encryptor::ReadInBuffer : Read %s from %d offset for data size %d", name, options.Offset, len(options.Data))

	fileHandle, err := os.OpenFile(e.mountPointCipher+name, os.O_RDONLY, 0666)
	if err != nil {
		log.Err("Encryptor::ReadAndDecryptBlock : Error opening encrypted file: %s", err.Error())
		return 0, err
	}
	defer fileHandle.Close()
	chunkIndex := options.Offset / int64(e.blockSize)
	encryptedChunkOffset := chunkIndex * (int64(e.blockSize) + MetaSize)
	encryptedChunk := make([]byte, e.blockSize+MetaSize)

	n, err := fileHandle.ReadAt(encryptedChunk, encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error reading encrypted file: %s", err.Error())
		return 0, err
	}

	log.Debug("Encryptor: Read %d bytes from encrypted file", n)

	plainText, err := DecryptChunk(encryptedChunk[NonceSize:], encryptedChunk[:NonceSize], e.encryptionKey)
	if err != nil {
		log.Err("Encryptor: Error decrypting file: %s", err.Error())
		return 0, err
	}

	copy(options.Data, plainText)
	length = int(dataLen)
	return
}

func (e *Encryptor) CreateDir(options internal.CreateDirOptions) error {
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