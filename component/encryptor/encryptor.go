package encryptor

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
	blockSize        uint64
	mountPointCipher string
	encryptionKey    []byte
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
	handle := handlemap.NewHandle(options.Name)
	if handle == nil {
		log.Trace("Encryptor::createFile : Failed to create handle for file: %s", options.Name)
		return nil, syscall.EFAULT
	}

	_, err := os.OpenFile(e.mountPointCipher+options.Name, os.O_RDWR|os.O_CREATE, options.Mode)
	if err != nil {
		log.Trace("Encryptor::createFile : Error creating file: %s", err.Error())
		return nil, err
	}
	handle.Mtime = time.Now()
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
		Size:   fileAttr.Size(),                   // Size
		Mode:   fileAttr.Mode(),                   // Permissions
		Path:   e.mountPointCipher + options.Name, // Full path
		Name:   fileAttr.Name(),                   // Base name of the path
	}
	if fileAttr.IsDir() {
		attr.Flags.Set(internal.PropFlagIsDir)
	}
	// Return the populated ObjAttr struct and nil error
	return attr, nil
}

func (e *Encryptor) StageData(opt internal.StageDataOptions) error {
	return e.EncryptWriteBlock(opt.Name, opt.Data, opt.Offset)
}

func (e *Encryptor) EncryptWriteBlock(name string, data []byte, blockId uint64) error {

	encryptedFile, err := os.OpenFile(e.mountPointCipher+name, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Info("Encryptor: Error opening encrypted file: %s", err.Error())
		return err
	}

	defer encryptedFile.Close()

	// Create AES cipher block
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return err
	}

	// Create AES-GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	// Generate a random nonce for each chunk
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	encryptedChunk := gcm.Seal(nil, nonce, data, nil)

	encryptedChunkOffset := int64(blockId) * (int64(e.blockSize) + int64(MetaSize))
	// Write the combined nonce and encrypted chunk
	n, err := encryptedFile.WriteAt(append(nonce, encryptedChunk...), encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error writing encrypted chunk to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset, n)
		return err
	}
	log.Info("Encryptor:: encryptWriteBlock: writing encrypted chunk to encrypted file: %s at offset %d : size of data %d, blockID %d ", name, encryptedChunkOffset, n, blockId)

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

func (e *Encryptor) ReadAndDecryptBlock(name string, offset int64, length int64, data []byte, encryptedFileSize int64) error {
	log.Trace("Encryptor::ReadAndDecryptBlock : Read %s from %d offset for data size %d encrypted file size %d", name, offset, length, encryptedFileSize)
	encryptedFile, err := os.Open(e.mountPointCipher + name)
	if err != nil {
		log.Info("Encryptor: Error opening encrypted file: %s", err.Error())
		return err
	}

	defer encryptedFile.Close()

	// Create AES cipher block
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return err
	}

	// Create AES-GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()

	chunkIndex := offset / int64(e.blockSize)
	encryptedChunkOffset := chunkIndex * (int64(e.blockSize) + int64(28))

	nextChunkOffset := (int64(nonceSize) + int64(e.blockSize) + int64(AuthTagSize) + encryptedChunkOffset)

	var encryptedChunk []byte
	if nextChunkOffset > encryptedFileSize { // last chunk
		encryptedChunk = make([]byte, encryptedFileSize-encryptedChunkOffset)
	} else {
		encryptedChunk = make([]byte, int64(nonceSize)+int64(e.blockSize)+int64(AuthTagSize))
	}
	log.Info("Encryptor:: encryptedFileSize: %d, offset %d , encryptedoffset %d, length of encrypted chunk size %d ", encryptedFileSize, offset, encryptedChunkOffset, len(encryptedChunk))

	n, err := encryptedFile.ReadAt(encryptedChunk, encryptedChunkOffset)
	if err != nil {
		log.Err("Encryptor: Error reading encrypted file: %s", err.Error())
		return err
	}

	log.Info("Encryptor: Read %d bytes from encrypted file", n)

	// Decrypt the chunk with AES-GCM
	decryptedChunk, err := gcm.Open(nil, encryptedChunk[:nonceSize], encryptedChunk[nonceSize:], nil)
	if err != nil {
		log.Err("Encryptor: Error decrypting file: %s", err.Error())
		return err
	}

	// Write the decrypted chunk to the data buffer
	copy(data, decryptedChunk)
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
