package encryptor

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
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
	handle           *handlemap.Handle
	blockSize        uint64
	mountPointCipher string
	encryptionKey    []byte
	endBlockIndex    int64 // keep track of the farthest block that has been written to the file
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

	// no block is written to the file yet
	e.endBlockIndex = -1

	return nil
}

func (e *Encryptor) Start(ctx context.Context) error {
	return nil
}
func (e *Encryptor) CommitData(opt internal.CommitDataOptions) error {
	//Commit is a no op for encryptor.
	return nil
}

func (e *Encryptor) CreateFile(options internal.CreateFileOptions) (*handlemap.Handle, error) {
	// Create the file in the mount point
	log.Info("Encryptor::createFile : %s", e.mountPointCipher+options.Name)
	e.handle = handlemap.NewHandle(options.Name)
	if e.handle == nil {
		log.Trace("Encryptor::createFile : Failed to create handle for file: %s", options.Name)
		return nil, syscall.EFAULT
	}

	fileHandle, err := os.OpenFile(e.mountPointCipher+options.Name, os.O_RDWR|os.O_CREATE, options.Mode)
	if err != nil {
		log.Trace("Encryptor::createFile : Error creating file: %s", err.Error())
		return nil, err
	}
	e.handle.FObj = fileHandle
	e.handle.Mtime = time.Now()
	// Set the file handle in the handle
	return e.handle, nil
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
	// check if file is multiple of block size
	if currentFileSize%(blockSize+MetaSize) == 0 {
		return (currentFileSize / (blockSize + MetaSize)) * blockSize, nil
	}

	// if not, read the last 8 bytes of file and check for padding
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
		log.Info("Encryptor::GetAttr : actual file size %d", actualFileSize)
		attr.Size = actualFileSize
	}
	return attr, nil
}

func (e *Encryptor) StageData(opt internal.StageDataOptions) error {
	log.Info("Encryptor::StageData : %s, offset %d, data %d", opt.Name, opt.Offset, len(opt.Data))
	return e.EncryptWriteBlock(opt.Name, opt.Data, opt.Offset)
}

func (e *Encryptor) EncryptWriteBlock(name string, data []byte, blockId uint64) error {

	e.handle.Lock()
	encryptedFile := e.handle.FObj

	paddingLength := 0
	if len(data) < int(e.blockSize) {
		// Pad the data to the block size
		paddingLength = int(e.blockSize) - len(data)
		data = append(data, make([]byte, paddingLength)...)
	}

	log.Info("Encryptor:: encryptWriteBlock: writing encrypted chunk to encrypted file: %s at offset %d : with padding length %d, blockID %d ", name, blockId*(e.blockSize+MetaSize), paddingLength, blockId)
	encryptedChunk, nonce, err := EncryptChunk(data, e.encryptionKey)
	if err != nil {
		log.Err("Encryptor: Error encrypting data: %s", err.Error())
		return err
	}

	encryptedChunkOffset := int64(blockId) * (int64(e.blockSize) + int64(MetaSize))
	// Write the combined nonce and encrypted chunk
	if paddingLength > 0 || int64(blockId) > e.endBlockIndex {
		paddingLengthByte := make([]byte, 8)
		binary.BigEndian.PutUint64(paddingLengthByte, uint64(paddingLength))
		n, err := encryptedFile.WriteAt(append(append(nonce, encryptedChunk...), paddingLengthByte...), encryptedChunkOffset)
		if err != nil {
			log.Err("Encryptor: Error writing encrypted chunk to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset, n)
			return err
		}
	} else {
		n, err := encryptedFile.WriteAt(append(nonce, encryptedChunk...), encryptedChunkOffset)
		if err != nil {
			log.Err("Encryptor: Error writing encrypted chunk to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset, n)
			return err
		}
	}
	if int64(blockId) > e.endBlockIndex {
		e.endBlockIndex = int64(blockId)
	}
	e.handle.Unlock()
	log.Info("Encryptor:: encryptWriteBlock: writing encrypted chunk to encrypted file: %s at offset %d ,blockID %d ", name, encryptedChunkOffset, blockId)

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

	err = e.ReadAndDecryptBlock(options.Handle.Path, options.Offset, dataLen, options.Data, options.Handle.Size)
	if err != nil {
		log.Err("Encryptor::ReadInBuffer : Failed to read %s [%s] from offset %d", options.Handle.Path, err.Error(), options.Offset)
		return 0, err
	}

	length = int(dataLen)
	return
}

func (e *Encryptor) ReadAndDecryptBlock(name string, offset int64, length int64, data []byte, fileSize int64) error {
	log.Trace("Encryptor::ReadAndDecryptBlock : Read %s from %d offset for data size %d encrypted file size %d", name, offset, length, fileSize)

	fileHandle, err := os.OpenFile(e.mountPointCipher+name, os.O_RDONLY, 0666)
	if err != nil {
		log.Err("Encryptor::ReadAndDecryptBlock : Error opening encrypted file: %s", err.Error())
		return err
	}
	defer fileHandle.Close()
	chunkIndex := offset / int64(e.blockSize)
	encryptedChunkOffset := chunkIndex * (int64(e.blockSize) + MetaSize)
	encryptedChunk := make([]byte, e.blockSize+MetaSize)
	log.Info("Encryptor:: fileSize: %d, offset %d , encryptedoffset %d, length of encrypted chunk size %d ", fileSize, offset, encryptedChunkOffset, len(encryptedChunk))

	n, err := fileHandle.ReadAt(encryptedChunk, encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error reading encrypted file: %s", err.Error())
		return err
	}

	log.Info("Encryptor: Read %d bytes from encrypted file", n)

	plainText, err := DecryptChunk(encryptedChunk[NonceSize:], encryptedChunk[:NonceSize], e.encryptionKey)
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
