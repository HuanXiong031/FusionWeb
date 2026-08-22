package httpx

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func removeUsedURL(urls []string, used map[string]struct{}) []string {
	var result []string
	for _, u := range urls {
		if _, ok := used[u]; !ok {
			result = append(result, u)
		}
	}
	return RemoveDuplicateElement(result)
}

// ResetUsedUrl is kept for old callers; URL retry state is local to CallHTTPx.
func ResetUsedUrl() {
}

func CallHTTPx(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int, taskID string, enableScreenshot bool) {
	nextUrls := RemoveDuplicateElement(urls)
	used := make(map[string]struct{}, len(nextUrls))

	times := 0
	for len(nextUrls) > 0 && times < 3 {
		options := runner.Options{
			Methods:                   "GET",
			InputTargetHost:           nextUrls,
			Favicon:                   true,
			Hashes:                    "md5",
			OutputServerHeader:        true,
			TLSProbe:                  true,
			MaxResponseBodySizeToRead: 1048576,
			FollowHostRedirects:       true,
			MaxRedirects:              5,
			ExtractTitle:              true,
			Timeout:                   timeout,
			Retries:                   3, // 从2次增加到3次，提高成功率
			HTTPProxy:                 proxy,
			NoFallbackScheme:          true,
			RandomAgent:               true,
			Threads:                   threads,
			Screenshot:                enableScreenshot,
			StoreResponse:             false,
			StoreResponseDir:          "",
		}

		if err := options.ValidateOptions(); err != nil {
			gologger.Error().Msgf("params error: %v", err)
		}

		httpxRunner, err := runner.New(&options)
		if err != nil {
			gologger.Error().Msgf("runner.New(&options) error: %v", err)
			return
		}

		httpxRunner.CallBack = callBack

		for _, u := range nextUrls {
			used[u] = struct{}{}
		}

		httpxRunner.RunEnumeration()
		nextUrls = removeUsedURL(httpxRunner.NextCheckUrl, used)
		httpxRunner.Close()
		times += 1

	}
}

func DirBrute(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int, taskID string, enableScreenshot bool) {
	urls = RemoveDuplicateElement(urls)

	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           urls,
		Hashes:                    "md5",
		OutputServerHeader:        true,
		TLSProbe:                  true,
		MaxResponseBodySizeToRead: 1048576,
		FollowHostRedirects:       true,
		MaxRedirects:              5,
		ExtractTitle:              true,
		Timeout:                   timeout,
		IsBrute:                   true,
		Retries:                   2,
		HTTPProxy:                 proxy,
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   threads,
		Screenshot:                enableScreenshot,
		StoreResponse:             false,
		StoreResponseDir:          "",
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("params error")
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		gologger.Error().Msgf("runner.New(&options) error")
	}
	httpxRunner.CallBack = callBack

	httpxRunner.RunEnumeration()
	httpxRunner.Close()
}
