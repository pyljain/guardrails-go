package utils

// Expressed as tokens*chars
const chunkSize = 25000 * 4

func Chunk(content string) []string {
	var batches []string

	len := len(content)
	for i := 0; i < len; i += chunkSize {
		end := i + chunkSize
		if end > len {
			end = len
		}
		batches = append(batches, content[i:end])
	}

	return batches
}
