package encryptor

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/Azure/azure-storage-fuse/v2/common/log"
	"github.com/Azure/azure-storage-fuse/v2/internal"
)

type Encryptor struct {
	internal.BaseComponent
}

type EncryptorOptions struct {
	BlockSize        uint64
	MountPointCipher string
	EncryptionKey    string
}

const (
	compName = "encryptor"
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
	return nil
}

func (e *Encryptor) Start(ctx context.Context) error {
	return nil
}
func (az *Encryptor) CommitData(opt internal.CommitDataOptions) error {
	//Commit is a no op for encryptor.
	return nil
}

func (e *Encryptor) StageData(opt internal.StageDataOptions) error {
	return encryptWriteBlock(opt.Name, opt.Data, opt.Offset)
}

func encryptWriteBlock(name string, data []byte, blockId uint64) error {
	// write the data to the file.

	var key, _ = base64.StdEncoding.DecodeString("kOwvAznCYUMcrs0qdET0gCIQmMPsl7EDgcbSVWlum6U=")
	var chunkSize = 1024 * 1024

	encryptedFile, err := os.OpenFile("/mnt/test1/"+name, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Info("Encryptor: Error opening encrypted file: %s", err.Error())
		return err
	}

	defer encryptedFile.Close()

	// Create AES cipher block
	block, err := aes.NewCipher(key)
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

	encryptedChunkOffset := int64(blockId) * (int64(chunkSize) + int64(28))

	n, err := encryptedFile.WriteAt(nonce, int64(encryptedChunkOffset))
	if err != nil {
		log.Err("Encryptor: Error writing nonce to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset, n)
		return err
	}
	log.Info("Encryptor:: encryptWriteBlock: writing encrypted chunk to encrypted file: %s at offset %d : size of data %d. blockId : %d ", name, encryptedChunkOffset, n, blockId)
	n, err = encryptedFile.WriteAt(encryptedChunk, int64(encryptedChunkOffset+int64(gcm.NonceSize())))
	if err != nil {
		log.Err("Encryptor: Error writing encrypted chunk to encrypted file: %s at offset %d : size of data %d", err.Error(), encryptedChunkOffset+int64(gcm.NonceSize()), n)
		return err
	}
	log.Info("Encryptor:: encryptWriteBlock: writing encrypted chunk to encrypted file: %s at offset %d : size of data %d, blockID %d ", name, encryptedChunkOffset+int64(gcm.NonceSize()), n, blockId)

	// Write the nonce, encrypted chunk, and authentication tag to the output file
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

	err = readAndDecryptBlock(options.Handle.Path, options.Offset, dataLen, options.Data, options.Handle.Size)
	if err != nil {
		log.Err("Encryptor::ReadInBuffer : Failed to read %s [%s] from offset %d", options.Handle.Path, err.Error(), options.Offset)
		return 0, err
	}

	length = int(dataLen)
	return
}

func readAndDecryptBlock(name string, offset int64, len int64, data []byte, encryptedFileSize int64) error {
	var key, _ = base64.StdEncoding.DecodeString("kOwvAznCYUMcrs0qdET0gCIQmMPsl7EDgcbSVWlum6U=")
	var chunkSize = 1024 * 1024
	var authTag = 16

	encryptedFile, err := os.Open("/mnt/test1/" + name)
	if err != nil {
		log.Info("Encryptor: Error opening encrypted file: %s", err.Error())
		return err
	}

	defer encryptedFile.Close()

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create AES-GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()

	// read data length + 28 byte from the file
	// decrypt the chunk and write to the output file

	chunkIndex := offset / int64(chunkSize)
	encryptedChunkOffset := chunkIndex * (int64(chunkSize) + int64(28))

	var encryptedChunk []byte
	if encryptedChunkOffset+len > encryptedFileSize { // last chunk}
		encryptedChunk = make([]byte, encryptedFileSize-encryptedChunkOffset)
	} else {
		encryptedChunk = make([]byte, int64(nonceSize)+int64(chunkSize)+int64(authTag))
	}
	log.Info("Encryptor:: encryptedFileSize: %d, offset %d , encryptedoffset %d", encryptedFileSize, offset, encryptedChunkOffset)

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

func (e *Encryptor) Stop() error {
	// clear the mount point.
	return nil
}

func NewEncryptorComponent() internal.Component {
	comp := &Encryptor{}
	comp.SetName(compName)
	return comp
}

func init() {
	internal.AddComponent(compName, NewEncryptorComponent)
	// Create a mount point for cipher text from config.
}
