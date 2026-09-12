package gitrepo

import (
	"bufio"
	"io"
)

const pipeBufSize = 1 << 20

func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, pipeBufSize) }

func newBufWriter(w io.Writer) *bufio.Writer { return bufio.NewWriterSize(w, 64<<10) }

func readFull(r io.Reader, buf []byte) (int, error) { return io.ReadFull(r, buf) }
