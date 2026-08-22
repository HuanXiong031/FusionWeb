package nuclei

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	nucleiUtils "github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/ratelimit"
)

// MockOutputWriter is a mocked output writer.
type MockOutputWriter struct {
	aurora          aurora.Aurora
	omitTemplate    bool
	RequestCallback func(templateID, url, requestType string, err error)
	FailureCallback func(result *output.InternalEvent)
	WriteCallback   func(o *output.ResultEvent)
}

// NewMockOutputWriter creates a new mock output writer
func NewMockOutputWriter(omitTemplate bool) *MockOutputWriter {
	return &MockOutputWriter{aurora: aurora.NewAurora(false), omitTemplate: omitTemplate}
}

// Close closes the output writer interface
func (m *MockOutputWriter) Close() {}

// Colorizer returns the colorizer instance for writer
func (m *MockOutputWriter) Colorizer() aurora.Aurora {
	return m.aurora
}

func (m *MockOutputWriter) ResultCount() int {
	return 0
}

// Write writes the event to file and/or screen.
func (m *MockOutputWriter) Write(result *output.ResultEvent) error {
	if m.WriteCallback != nil {
		m.WriteCallback(result)
	}
	return nil
}

// Request writes a log the requests trace log
func (m *MockOutputWriter) Request(templateID, url, requestType string, err error) {
	if m.RequestCallback != nil {
		m.RequestCallback(templateID, url, requestType, err)
	}
}

// WriteFailure writes the event to file and/or screen.
func (m *MockOutputWriter) WriteFailure(wrappedEvent *output.InternalWrappedEvent) error {
	if len(wrappedEvent.Results) > 0 {
		for _, result := range wrappedEvent.Results {
			result.MatcherStatus = false
			if err := m.Write(result); err != nil {
				return err
			}
		}
		return nil
	}
	if m.FailureCallback != nil {
		m.FailureCallback(&wrappedEvent.InternalEvent)
	}
	return nil
}

func (m *MockOutputWriter) RequestStatsLog(statusCode, response string) {}

func (m *MockOutputWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}

// MockProgressClient is a mocked progress client.
type MockProgressClient struct{}

// Stop stops the progress recorder.
func (m *MockProgressClient) Stop() {}

// Init inits the progress bar with initial details for scan
func (m *MockProgressClient) Init(hostCount int64, rulesCount int, requestCount int64) {}

// AddToTotal adds a value to the total request count
func (m *MockProgressClient) AddToTotal(delta int64) {}

// IncrementRequests increments the requests counter by 1.
func (m *MockProgressClient) IncrementRequests() {}

// SetRequests sets the counter by incrementing it with a delta
func (m *MockProgressClient) SetRequests(count uint64) {}

// IncrementMatched increments the matched counter by 1.
func (m *MockProgressClient) IncrementMatched() {}

// IncrementErrorsBy increments the error counter by count.
func (m *MockProgressClient) IncrementErrorsBy(count int64) {}

// IncrementFailedRequestsBy increments the number of requests counter by count
// along with errors.
func (m *MockProgressClient) IncrementFailedRequestsBy(count int64) {}

// applyRequiredDefaults to options
func (e *NucleiEngine) applyRequiredDefaults(ctx context.Context) {
	mockoutput := NewMockOutputWriter(e.opts.OmitTemplate)
	mockoutput.WriteCallback = func(event *output.ResultEvent) {
		if len(e.resultCallbacks) > 0 {
			for _, callback := range e.resultCallbacks {
				if callback != nil {
					callback(event)
				}
			}
			return
		}
		sb := strings.Builder{}
		sb.WriteString(fmt.Sprintf("[%v] ", event.TemplateID))
		if event.Matched != "" {
			sb.WriteString(event.Matched)
		} else {
			sb.WriteString(event.Host)
		}
		fmt.Println(sb.String())
	}
	if e.onFailureCallback != nil {
		mockoutput.FailureCallback = e.onFailureCallback
	}

	if e.customWriter != nil {
		e.customWriter = output.NewMultiWriter(e.customWriter, mockoutput)
	} else {
		e.customWriter = mockoutput
	}

	if e.customProgress == nil {
		e.customProgress = &MockProgressClient{}
	}
	if e.hostErrCache == nil && e.opts.ShouldUseHostError() {
		e.hostErrCache = hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	}
	// setup interactsh
	if e.interactshOpts != nil {
		e.interactshOpts.Output = e.customWriter
		e.interactshOpts.Progress = e.customProgress
	} else {
		e.interactshOpts = interactsh.DefaultOptions(e.customWriter, e.rc, e.customProgress)
	}
	if e.rateLimiter == nil {
		e.rateLimiter = ratelimit.New(ctx, 150, time.Second)
	}
	if e.opts.ExcludeTags == nil {
		e.opts.ExcludeTags = []string{}
	}
	// these templates are known to have weak matchers
	// and idea is to disable them to avoid false positives
	e.opts.ExcludeTags = append(e.opts.ExcludeTags, config.ReadIgnoreFile().Tags...)

	e.inputProvider = provider.NewSimpleInputProvider()
}

// init
func (e *NucleiEngine) init(ctx context.Context) error {
	// Update logger ref (if it was changed by [WithLogger])
	// (Logger is already initialized)
	if e.opts.Logger != e.Logger {
		e.Logger = e.opts.Logger
	}

	if e.opts.Verbose {
		e.Logger.SetMaxLevel(levels.LevelVerbose)
	} else if e.opts.Debug {
		e.Logger.SetMaxLevel(levels.LevelDebug)
	} else if e.opts.Silent {
		e.Logger.SetMaxLevel(levels.LevelSilent)
	}

	if err := runner.ValidateOptions(e.opts); err != nil {
		return err
	}

	if e.opts.Parser != nil {
		if op, ok := e.opts.Parser.(*templates.Parser); ok {
			e.parser = op
		}
	}

	if e.parser == nil {
		e.parser = templates.NewParser()
	}

	if protocolstate.ShouldInit(e.opts.ExecutionId) {
		_ = protocolinit.Init(e.opts)
	}

	if e.opts.ProxyInternal && e.opts.AliveHttpProxy != "" || e.opts.AliveSocksProxy != "" {
		httpclient, err := httpclientpool.Get(e.opts, &httpclientpool.Configuration{})
		if err != nil {
			return err
		}
		e.httpClient = httpclient
	}

	e.applyRequiredDefaults(ctx)
	var err error

	// setup progressbar
	if e.enableStats {
		progressInstance, progressErr := progress.NewStatsTicker(e.opts.StatsInterval, e.enableStats, e.opts.StatsJSON, false, e.opts.MetricsPort)
		if progressErr != nil {
			return err
		}
		e.customProgress = progressInstance
		e.interactshOpts.Progress = progressInstance
	}

	if err := reporting.CreateConfigIfNotExists(); err != nil {
		return err
	}
	// we don't support reporting config in sdk mode
	if e.rc, err = reporting.New(&reporting.Options{}, "", false); err != nil {
		return err
	}
	e.interactshOpts.IssuesClient = e.rc
	if e.httpClient != nil {
		e.interactshOpts.HTTPClient = e.httpClient
	}
	if e.interactshClient, err = interactsh.New(e.interactshOpts); err != nil {
		return err
	}

	if e.opts.Headless {
		if engine.MustDisableSandbox() {
			e.Logger.Warning().Msgf("The current platform and privileged user will run the browser without sandbox")
		}
		browser, err := engine.New(e.opts)
		if err != nil {
			return err
		}
		e.browserInstance = browser
	}

	if e.catalog == nil {
		e.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	}

	if e.tmpDir == "" {
		tmpDir, err := os.MkdirTemp("", "nuclei-tmp-*")
		if err != nil {
			return err
		}
		e.tmpDir = tmpDir
	}

	e.executerOpts = &protocols.ExecutorOptions{
		Output:             e.customWriter,
		Options:            e.opts,
		Progress:           e.customProgress,
		Catalog:            e.catalog,
		IssuesClient:       e.rc,
		RateLimiter:        e.rateLimiter,
		Interactsh:         e.interactshClient,
		Colorizer:          aurora.NewAurora(true),
		ResumeCfg:          types.NewResumeCfg(),
		Browser:            e.browserInstance,
		Parser:             e.parser,
		InputHelper:        input.NewHelper(),
		TemporaryDirectory: e.tmpDir,
		Logger:             e.opts.Logger,
	}
	if e.opts.ShouldUseHostError() && e.hostErrCache != nil {
		e.executerOpts.HostErrorsCache = e.hostErrCache
	}
	if len(e.opts.SecretsFile) > 0 {
		authTmplStore, err := runner.GetAuthTmplStore(e.opts, e.catalog, e.executerOpts)
		if err != nil {
			return errors.Wrap(err, "failed to load dynamic auth templates")
		}
		authOpts := &authprovider.AuthProviderOptions{SecretsFiles: e.opts.SecretsFile}
		authOpts.LazyFetchSecret = runner.GetLazyAuthFetchCallback(&runner.AuthLazyFetchOptions{
			TemplateStore: authTmplStore,
			ExecOpts:      e.executerOpts,
		})
		// initialize auth provider
		provider, err := authprovider.NewAuthProvider(authOpts)
		if err != nil {
			return errors.Wrap(err, "could not create auth provider")
		}
		e.executerOpts.AuthProvider = provider
	}
	if e.authprovider != nil {
		e.executerOpts.AuthProvider = e.authprovider
	}

	// prefetch secrets
	if e.executerOpts.AuthProvider != nil && e.opts.PreFetchSecrets {
		if err := e.executerOpts.AuthProvider.PreFetchSecrets(); err != nil {
			return errors.Wrap(err, "could not prefetch secrets")
		}
	}

	if e.executerOpts.RateLimiter == nil {
		if e.opts.RateLimitMinute > 0 {
			e.opts.RateLimit = e.opts.RateLimitMinute
			e.opts.RateLimitDuration = time.Minute
		}
		if e.opts.RateLimit > 0 && e.opts.RateLimitDuration == 0 {
			e.opts.RateLimitDuration = time.Second
		}
		if e.opts.RateLimit == 0 && e.opts.RateLimitDuration == 0 {
			e.executerOpts.RateLimiter = ratelimit.NewUnlimited(ctx)
		} else {
			e.executerOpts.RateLimiter = ratelimit.New(ctx, uint(e.opts.RateLimit), e.opts.RateLimitDuration)
		}
	}

	// Handle the case where the user passed an existing parser that we can use as a cache
	if e.opts.Parser != nil {
		if cachedParser, ok := e.opts.Parser.(*templates.Parser); ok {
			e.parser = cachedParser
			e.opts.Parser = cachedParser
			e.executerOpts.Parser = cachedParser
			e.executerOpts.Options.Parser = cachedParser
		}
	}

	// Create a new parser if necessary
	if e.parser == nil {
		op := templates.NewParser()
		e.parser = op
		e.opts.Parser = op
		e.executerOpts.Parser = op
		e.executerOpts.Options.Parser = op
	}

	e.engine = core.New(e.opts)
	e.engine.SetExecuterOptions(e.executerOpts)

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = 5 * time.Second
	if client, err := httpx.New(&httpxOptions); err != nil {
		return err
	} else {
		e.httpxClient = nucleiUtils.GetInputLivenessChecker(client)
	}

	// Only Happens once regardless how many times this function is called
	// This will update ignore file to filter out templates with weak matchers to avoid false positives
	// and also upgrade templates to latest version if available
	installer.NucleiSDKVersionCheck()

	if DefaultConfig.CanCheckForUpdates() {
		return e.processUpdateCheckResults()
	}
	return nil
}

type syncOnce struct {
	sync.Once
}

var updateCheckInstance = &syncOnce{}

// processUpdateCheckResults processes update check results
func (e *NucleiEngine) processUpdateCheckResults() error {
	var err error
	updateCheckInstance.Do(func() {
		if e.onUpdateAvailableCallback != nil {
			e.onUpdateAvailableCallback(config.DefaultConfig.LatestNucleiTemplatesVersion)
		}
		tm := installer.TemplateManager{}
		err = tm.UpdateIfOutdated()
	})
	return err
}
