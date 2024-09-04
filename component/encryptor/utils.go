package encryptor

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"github.com/Azure/azure-storage-fuse/v2/common/log"
	"github.com/Azure/azure-storage-fuse/v2/internal"
)

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

func getFileHandleAndLastChunkMeta(handleMap *sync.Map, lastChunkMetaMap *sync.Map, fileName string) (*os.File, *LastChunkMeta, error) {
	fileValue, ok := handleMap.Load(fileName)
	if !ok {
		return nil, nil, fmt.Errorf("file handle not found for %s", fileName)
	}

	fileHandle, ok := fileValue.(*os.File)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected type for file handle of %s", fileName)
	}

	metaValue, ok := lastChunkMetaMap.Load(fileName)
	if !ok {
		return nil, nil, fmt.Errorf("last chunk meta not found for %s", fileName)
	}

	lastChunkMeta, ok := metaValue.(*LastChunkMeta)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected type for last chunk meta of %s", fileName)
	}

	return fileHandle, lastChunkMeta, nil
}
