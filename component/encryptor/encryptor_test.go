package encryptor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-storage-fuse/v2/common"
	"github.com/Azure/azure-storage-fuse/v2/common/config"
	"github.com/Azure/azure-storage-fuse/v2/common/log"
	"github.com/Azure/azure-storage-fuse/v2/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var ctx = context.Background()

const (
	KB        = 1024
	MB        = 1024 * KB
	GB        = 1024 * MB
	BlockSize = 1 * MB
	mountPath = "unit/"
)

type encryptorTestSuite struct {
	suite.Suite
	assert    *assert.Assertions
	encryptor *Encryptor
}

type encryptorTestConfig struct {
	BlockSize          uint64 `json:"block-size-mb"`
	EncryptionKey      string `json:"encryption-key"`
	EncryptedMountPath string `json:"encrypted-mount-path"`
}

var testConfig encryptorTestConfig

func NewTestEncryptor(configuration string) (*Encryptor, error) {
	confReader := strings.NewReader(configuration)
	err := config.ReadConfigFromReader(confReader)
	if err != nil {
		log.Err("Failed to read config from reader, error: %s", err.Error())
		return nil, err
	}
	e := NewEncryptorComponent()
	err = e.Configure(true)

	return e.(*Encryptor), err
}

func generateDirectoryName() string {
	return "dir" + randomString(8)
}

func generateFileName() string {
	return "file" + randomString(8)
}

func randomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:length]
}

func writeToFile(fileHandle *os.File, data []byte) error {
	encryptionKey, err := base64.StdEncoding.DecodeString(testConfig.EncryptionKey)
	if err != nil {
		fmt.Println("Error decoding encryption key", err)
		return err
	}
	paddingLength := int64(0)
	fileSize := len(data)
	totalBlocks := fileSize/BlockSize + 1
	if fileSize%BlockSize != 0 {
		paddingLength = int64(BlockSize) - int64(fileSize%BlockSize)
		data = append(data, make([]byte, paddingLength)...)
	}

	for i := 0; i < totalBlocks; i++ {
		encryptedChunk, nonce, err := EncryptChunk(data[i*BlockSize:(i+1)*BlockSize], encryptionKey)
		if err != nil {
			fmt.Println("Error encrypting chunk", err)
			return err
		}
		encryptedChunkWithNonce := append(nonce, encryptedChunk...)
		n, err := fileHandle.WriteAt(encryptedChunkWithNonce, int64(i*(BlockSize+MetaSize)))
		if err != nil {
			fmt.Println("Error writing to file chunk number", i, err)
			return err
		}
		fmt.Println("Wrote", n, "bytes to file")
	}
	paddingLengthByte := make([]byte, 8)
	binary.BigEndian.PutUint64(paddingLengthByte, uint64(paddingLength))
	_, err = fileHandle.WriteAt(paddingLengthByte, int64(totalBlocks*(BlockSize+MetaSize)))
	if err != nil {
		fmt.Println("Error writing padding length to file", err)
		return err
	}

	return nil
}

func (s *encryptorTestSuite) SetupTest() {
	cfg := common.LogConfig{
		FilePath:    "./logfile.txt",
		MaxFileSize: 10,
		FileCount:   10,
		Level:       common.ELogLevel.LOG_DEBUG(),
	}
	_ = log.SetDefaultLogger("base", cfg)

	cfgFile, err := os.Open("./encryptortest.json")
	if err != nil {
		fmt.Println("Unable to open config file", err)
		os.Exit(1)
	}
	defer cfgFile.Close()

	cfgData, err := io.ReadAll(cfgFile)
	if err != nil {
		fmt.Println("Unable to read config file", err)
		os.Exit(1)
	}
	err = json.Unmarshal(cfgData, &testConfig)
	if err != nil {
		fmt.Println("Unable to unmarshal config file", err)
		os.Exit(1)
	}

	err = os.Mkdir(mountPath, 0777)
	if err != nil && !os.IsExist(err) {
		fmt.Println("Unable to create mount path", err)
		os.Exit(1)
	}

	configuration := fmt.Sprintf("encryptor:\n block-size-mb: %d \n encrypted-mount-path: %s\n encryption-key: %s",
		testConfig.BlockSize, testConfig.EncryptedMountPath, testConfig.EncryptionKey)
	s.assert = assert.New(s.T())
	s.encryptor, err = NewTestEncryptor(configuration)
	if err != nil {
		fmt.Println("Unable to create encryptor", err)
		os.Exit(1)
	}
	s.encryptor.Start(ctx)
}

func (s *encryptorTestSuite) TestCreateFile() {
	name := generateFileName()
	h, err := s.encryptor.CreateFile(internal.CreateFileOptions{Name: name})
	s.assert.Nil(err)
	s.assert.NotNil(h)
	s.assert.Equal(name, h.Path)

	// verify file exists
	_, err = os.Stat(mountPath + name)
	s.assert.Nil(err)

	os.Remove(mountPath + name)
}

func (s *encryptorTestSuite) TestCreateDir() {
	var paths = []string{generateDirectoryName(), generateDirectoryName() + "/"}
	for _, path := range paths {
		log.Debug(path)
		s.Run(path, func() {
			err := s.encryptor.CreateDir(internal.CreateDirOptions{Name: path})

			s.assert.Nil(err)
			fs, err := os.Stat(mountPath + path)
			s.assert.Nil(err)
			s.assert.True(fs.IsDir())

		})
	}
}

func (s *encryptorTestSuite) TestCreateFileWithParent() {
	dir := generateDirectoryName()
	os.Mkdir(mountPath+dir, 0777)
	name := generateFileName()
	h, err := s.encryptor.CreateFile(internal.CreateFileOptions{Name: dir + "/" + name})
	s.assert.Nil(err)
	s.assert.NotNil(h)
	s.assert.Equal(dir+"/"+name, h.Path)

	// verify file exists
	_, err = os.Stat(mountPath + dir + "/" + name)
	s.assert.Nil(err)

	os.RemoveAll(mountPath + dir)
}

func (s *encryptorTestSuite) TestGetAttr() {
	name := generateFileName()
	h, err := s.encryptor.CreateFile(internal.CreateFileOptions{Name: name, Mode: 0666})
	s.assert.Nil(err)
	s.assert.NotNil(h)
	s.assert.Equal(name, h.Path)

	fileSize := int64(9*MB + 512*KB)
	data := make([]byte, fileSize)
	_, err = rand.Read(data)
	s.assert.Nil(err)

	_, err = rand.Read(data)
	s.assert.Nil(err)
	totalBlocks := int(fileSize/BlockSize + 1)

	for i := 0; i < totalBlocks; i++ {
		var chunk []byte
		if i == totalBlocks-1 {
			chunk = data[i*BlockSize:]
		} else {
			chunk = data[i*BlockSize : (i+1)*BlockSize]
		}
		err = s.encryptor.StageData(internal.StageDataOptions{
			Name:   name,
			Offset: uint64(i),
			Data:   chunk})
		s.assert.Nil(err)
	}

	_, err = os.Stat(mountPath + name)
	s.assert.Nil(err)
	s.assert.Nil(err)
	attr, err := s.encryptor.GetAttr(internal.GetAttrOptions{Name: name})
	s.assert.Nil(err)
	s.assert.Equal(fileSize, attr.Size)
}

func (s *encryptorTestSuite) TestReadInbuffer() {
	name := generateFileName()
	h, err := s.encryptor.CreateFile(internal.CreateFileOptions{Name: name, Mode: 0666})
	h.Size = 9*MB + 512*KB
	s.assert.Nil(err)
	s.assert.NotNil(h)
	s.assert.Equal(name, h.Path)

	fileSize := int64(9*MB + 512*KB)
	totalBlocks := int(fileSize/BlockSize + 1)
	dataWritten := make([]byte, fileSize)
	_, err = rand.Read(dataWritten)
	s.assert.Nil(err)
	handle, ok := s.encryptor.handleMap.Load(name)
	s.assert.True(ok)
	err = writeToFile(handle.(*os.File), dataWritten)
	s.assert.Nil(err)

	s.assert.Nil(err)

	chunk := make([]byte, 1*MB)
	for i := 0; i < totalBlocks; i++ {
		n, err := s.encryptor.ReadInBuffer(internal.ReadInBufferOptions{Handle: h, Offset: int64(i * BlockSize), Data: chunk})
		s.assert.Nil(err)

		s.assert.True(bytes.Equal(chunk[:n], dataWritten[i*MB:i*MB+n]))
	}
}

func (s *encryptorTestSuite) TestStageData() {
	name := generateFileName()
	h, err := s.encryptor.CreateFile(internal.CreateFileOptions{Name: name, Mode: 0666})
	s.assert.Nil(err)
	s.assert.NotNil(h)

	fileSize := int64(9*MB + 512*KB)
	data := make([]byte, fileSize)
	_, err = rand.Read(data)
	s.assert.Nil(err)
	totalBlocks := int(fileSize/BlockSize + 1)

	for i := 0; i < totalBlocks; i++ {
		var chunk []byte
		if i == totalBlocks-1 {
			chunk = data[i*BlockSize:]
		} else {
			chunk = data[i*BlockSize : (i+1)*BlockSize]
		}
		err = s.encryptor.StageData(internal.StageDataOptions{
			Name:   name,
			Offset: uint64(i),
			Data:   chunk})
		s.assert.Nil(err)
	}

	_, err = os.Stat(mountPath + name)
	s.assert.Nil(err)

	fileHandle, err := os.OpenFile(mountPath+name, os.O_RDONLY, 0666)
	s.assert.Nil(err)
	defer fileHandle.Close()

	for i := 0; i < totalBlocks; i++ {
		encryptedChunk := make([]byte, BlockSize+MetaSize)
		_, err = fileHandle.ReadAt(encryptedChunk, int64(i*(BlockSize+MetaSize)))
		s.assert.Nil(err)
		nonce := encryptedChunk[:NonceSize]
		encryptedData := encryptedChunk[NonceSize:]
		decryptedData, err := DecryptChunk(encryptedData, nonce, s.encryptor.encryptionKey)
		s.assert.Nil(err)
		if i == totalBlocks-1 {
			s.assert.True(bytes.Equal(data[i*BlockSize:], decryptedData[:len(data[i*BlockSize:])]))
		} else {
			s.assert.True(bytes.Equal(data[i*BlockSize:(i+1)*BlockSize], decryptedData))
		}
	}
}

func (s *encryptorTestSuite) TestParallelWrites() {

	var wg sync.WaitGroup
	fileCount := 3
	// create a list of file which will have names of the files created
	var files []string
	for count := 0; count < fileCount; count++ {
		files = append(files, generateFileName())
	}

	fileSize := int64(9*MB + 512*KB)
	data := make([]byte, fileSize)
	_, err := rand.Read(data)
	s.assert.Nil(err)
	totalBlocks := int(fileSize/BlockSize + 1)
	for _, name := range files {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			h, err := s.encryptor.CreateFile(internal.CreateFileOptions{Name: name, Mode: 0666})
			s.assert.Nil(err)
			s.assert.NotNil(h)

			for i := 0; i < totalBlocks; i++ {
				var chunk []byte
				if i == totalBlocks-1 {
					chunk = data[i*BlockSize:]
				} else {
					chunk = data[i*BlockSize : (i+1)*BlockSize]
				}
				err = s.encryptor.StageData(internal.StageDataOptions{
					Name:   name,
					Offset: uint64(i),
					Data:   chunk})
				s.assert.Nil(err)
			}
		}(name)
	}
	wg.Wait()
	fmt.Println("All files created and validated successfully.")

	for _, name := range files {
		_, err = os.Stat(mountPath + name)
		s.assert.Nil(err)

		fileHandle, err := os.OpenFile(mountPath+name, os.O_RDONLY, 0666)
		s.assert.Nil(err)
		defer fileHandle.Close()

		for i := 0; i < totalBlocks; i++ {
			encryptedChunk := make([]byte, BlockSize+MetaSize)
			_, err = fileHandle.ReadAt(encryptedChunk, int64(i*(BlockSize+MetaSize)))
			s.assert.Nil(err)
			nonce := encryptedChunk[:NonceSize]
			encryptedData := encryptedChunk[NonceSize:]
			decryptedData, err := DecryptChunk(encryptedData, nonce, s.encryptor.encryptionKey)
			s.assert.Nil(err)
			if i == totalBlocks-1 {
				s.assert.True(bytes.Equal(data[i*BlockSize:], decryptedData[:len(data[i*BlockSize:])]))
			} else {
				s.assert.True(bytes.Equal(data[i*BlockSize:(i+1)*BlockSize], decryptedData))
			}
		}
	}
}

func TestEncryptor(t *testing.T) {
	suite.Run(t, new(encryptorTestSuite))
}

func (s *encryptorTestSuite) AfterTest(suiteName, testName string) {
	os.RemoveAll(mountPath)
}
