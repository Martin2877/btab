package options

type ArgsOptions struct {
	TemplateFilePath string
	FilePath         string
	Content          string
}
type ArgsOption func(options *ArgsOptions)

func WithTemplateFilePath(key string) ArgsOption {
	return func(options *ArgsOptions) {
		options.TemplateFilePath = key
	}
}

func WithFilePath(key string) ArgsOption {
	return func(options *ArgsOptions) {
		options.FilePath = key
	}
}

func WithContent(key string) ArgsOption {
	return func(options *ArgsOptions) {
		options.Content = key
	}
}
