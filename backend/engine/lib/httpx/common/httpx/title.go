package httpx

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/text/encoding/simplifiedchinese"
)

var (
	cutset           = "\n\t\v\f\r"
	reTitle          = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
	reContentType    = regexp.MustCompile(`(?im)\s*charset="(.*?)"|charset=(.*?)"\s*`)
	maxTitleLength   = 100  // 标题最大长度（参考fscan）
	emptyTitleText   = "\"\"" // 空标题表示
	noTitleText      = "无标题" // 无标题表示
)

// ExtractTitle from a response
// 增强版标题提取，借鉴fscan的优化（GBK编码、长度限制、特殊字符处理）
func ExtractTitle(r *Response) (title string) {
	// 检测并转换GBK编码（中文网站常用）
	body := r.Data
	if !utf8.Valid(body) {
		// 尝试GBK转UTF-8
		if converted, err := simplifiedchinese.GBK.NewDecoder().Bytes(body); err == nil {
			body = converted
			// 使用转换后的内容重新解析
			r.Data = body
			r.Raw = string(body)
		}
	}

	// Try to parse the DOM
	titleDom, err := getTitleWithDom(r)
	// In case of error fallback to regex
	if err != nil {
		for _, match := range reTitle.FindAllString(r.Raw, -1) {
			title = match
			break
		}
	} else {
		title = renderNode(titleDom)
	}

	title = html.UnescapeString(trimTitleTags(title))

	// 增强的清理逻辑（借鉴fscan）
	title = cleanTitle(title)

	return title
}

func getTitleWithDom(r *Response) (*html.Node, error) {
	var title *html.Node
	var crawler func(*html.Node)
	crawler = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "title" {
			title = node
			return
		}
		for child := node.FirstChild; child != nil && title == nil; child = child.NextSibling {
			crawler(child)
		}
	}
	htmlDoc, err := html.Parse(bytes.NewReader(r.Data))
	if err != nil {
		return nil, err
	}
	crawler(htmlDoc)
	if title != nil {
		return title, nil
	}
	return nil, fmt.Errorf("title not found")
}

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	html.Render(w, n) //nolint
	return buf.String()
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	if titleEnd < 0 || titleBegin < 0 {
		return title
	}
	return title[titleBegin+1 : titleEnd]
}

// cleanTitle 清理标题内容（借鉴fscan的实现）
func cleanTitle(title string) string {
	// 去除空白字符
	title = strings.TrimSpace(strings.Trim(title, cutset))
	
	// 去除换行符和回车符
	title = strings.Replace(title, "\n", "", -1)
	title = strings.Replace(title, "\r", "", -1)
	
	// HTML特殊字符处理
	title = strings.Replace(title, "&nbsp;", " ", -1)
	title = strings.Replace(title, "&lt;", "<", -1)
	title = strings.Replace(title, "&gt;", ">", -1)
	title = strings.Replace(title, "&amp;", "&", -1)
	title = strings.Replace(title, "&quot;", "\"", -1)
	
	// 截断过长的标题（参考fscan的maxTitleLength=100）
	if len(title) > maxTitleLength {
		title = title[:maxTitleLength]
	}
	
	// 处理空标题情况
	if title == "" {
		return emptyTitleText
	}
	
	return title
}
