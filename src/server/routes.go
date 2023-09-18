package server

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/autometrics-dev/autometrics-go/otel/autometrics"
	"github.com/nkanaev/yarr/src/assets"
	"github.com/nkanaev/yarr/src/content/htmlutil"
	"github.com/nkanaev/yarr/src/content/readability"
	"github.com/nkanaev/yarr/src/content/sanitizer"
	"github.com/nkanaev/yarr/src/content/silo"
	"github.com/nkanaev/yarr/src/server/auth"
	"github.com/nkanaev/yarr/src/server/gzip"
	"github.com/nkanaev/yarr/src/server/opml"
	"github.com/nkanaev/yarr/src/server/router"
	"github.com/nkanaev/yarr/src/storage"
	"github.com/nkanaev/yarr/src/worker"
)

//go:generate autometrics --otel

func (s *Server) handler() http.Handler {
	r := router.NewRouter(s.BasePath)

	r.Use(gzip.Middleware)

	if s.Username != "" && s.Password != "" {
		a := &auth.Middleware{
			BasePath: s.BasePath,
			Username: s.Username,
			Password: s.Password,
			Public:   []string{"/static", "/fever"},
		}
		r.Use(a.Handler)
	}

	r.For("/", s.handleIndex)
	r.For("/manifest.json", s.handleManifest)
	r.For("/static/*path", s.handleStatic)
	r.For("/api/status", s.handleStatus)
	r.For("/api/folders", s.handleFolderList)
	r.For("/api/folders/:id", s.handleFolder)
	r.For("/api/feeds", s.handleFeedList)
	r.For("/api/feeds/refresh", s.handleFeedRefresh)
	r.For("/api/feeds/errors", s.handleFeedErrors)
	r.For("/api/feeds/:id/icon", s.handleFeedIcon)
	r.For("/api/feeds/:id", s.handleFeed)
	r.For("/api/items", s.handleItemList)
	r.For("/api/items/:id", s.handleItem)
	r.For("/api/settings", s.handleSettings)
	r.For("/opml/import", s.handleOPMLImport)
	r.For("/opml/export", s.handleOPMLExport)
	r.For("/page", s.handlePageCrawl)
	r.For("/logout", s.handleLogout)
	r.For("/fever/", s.handleFever)

	return r
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleIndex` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleIndex`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleIndex%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleIndex%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleIndex%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleIndex%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleIndex%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleIndex%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleIndex%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleIndex%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleIndex%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleIndex%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleIndex%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleIndex%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleIndex%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleIndex%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleIndex%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "Root" --latency-target 99 --latency-ms 5
func (s *Server) handleIndex(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("Root"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	c.HTML(http.StatusOK, assets.Template("index.html"), map[string]interface{}{
		"settings":      s.db.GetSettings(),
		"authenticated": s.Username != "" && s.Password != "",
	})
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleStatic` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleStatic`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleStatic%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleStatic%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleStatic%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleStatic%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleStatic%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleStatic%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleStatic%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleStatic%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleStatic%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleStatic%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleStatic%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleStatic%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleStatic%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleStatic%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleStatic%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "Static" --latency-target 99 --latency-ms 5
func (s *Server) handleStatic(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("Static"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	// don't serve templates
	dir, name := filepath.Split(c.Vars["path"])
	if dir == "" && strings.HasSuffix(name, ".html") {
		c.Out.WriteHeader(http.StatusNotFound)
		return
	}
	http.StripPrefix(s.BasePath+"/static/", http.FileServer(http.FS(assets.FS))).ServeHTTP(c.Out, c.Req)
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleManifest` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleManifest`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleManifest%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleManifest%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleManifest%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleManifest%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleManifest%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleManifest%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleManifest%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleManifest%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleManifest%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleManifest%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleManifest%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleManifest%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleManifest%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleManifest%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleManifest%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "Manifest" --latency-target 99 --latency-ms 5
func (s *Server) handleManifest(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("Manifest"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	c.JSON(http.StatusOK, map[string]interface{}{
		"$schema":     "https://json.schemastore.org/web-manifest-combined.json",
		"name":        "yarr!",
		"short_name":  "yarr",
		"description": "yet another rss reader",
		"display":     "standalone",
		"start_url":   s.BasePath,
		"icons": []map[string]interface{}{
			{
				"src":   s.BasePath + "/static/graphicarts/favicon.png",
				"sizes": "64x64",
				"type":  "image/png",
			},
		},
	})
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleStatus` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleStatus`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleStatus%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleStatus%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleStatus%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleStatus%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleStatus%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleStatus%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleStatus%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleStatus%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleStatus%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleStatus%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleStatus%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleStatus%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleStatus%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleStatus%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleStatus%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleStatus(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	c.JSON(http.StatusOK, map[string]interface{}{
		"running": s.worker.FeedsPending(),
		"stats":   s.db.FeedStats(),
	})
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFolderList` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFolderList`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFolderList%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFolderList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFolderList%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFolderList%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFolderList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFolderList%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFolderList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFolderList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFolderList%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFolderList%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFolderList%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFolderList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFolderList%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFolderList%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFolderList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFolderList(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "GET" {
		list := s.db.ListFolders()
		c.JSON(http.StatusOK, list)
	} else if c.Req.Method == "POST" {
		var body FolderCreateForm
		if err := json.NewDecoder(c.Req.Body).Decode(&body); err != nil {
			log.Print(err)
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body.Title) == 0 {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "Folder title missing."})
			return
		}
		folder := s.db.CreateFolder(body.Title)
		c.JSON(http.StatusCreated, folder)
	} else {
		c.Out.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFolder` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFolder`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFolder%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFolder%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFolder%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFolder%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFolder%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFolder%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFolder%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFolder%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFolder%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFolder%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFolder%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFolder%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFolder%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFolder%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFolder%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFolder(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	id, err := c.VarInt64("id")
	if err != nil {
		c.Out.WriteHeader(http.StatusBadRequest)
		return
	}
	if c.Req.Method == "PUT" {
		var body FolderUpdateForm
		if err := json.NewDecoder(c.Req.Body).Decode(&body); err != nil {
			log.Print(err)
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Title != nil {
			s.db.RenameFolder(id, *body.Title)
		}
		if body.IsExpanded != nil {
			s.db.ToggleFolderExpanded(id, *body.IsExpanded)
		}
		c.Out.WriteHeader(http.StatusOK)
	} else if c.Req.Method == "DELETE" {
		s.db.DeleteFolder(id)
		c.Out.WriteHeader(http.StatusNoContent)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFeedRefresh` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFeedRefresh`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFeedRefresh%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedRefresh%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFeedRefresh%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedRefresh%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedRefresh%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFeedRefresh%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedRefresh%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedRefresh%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFeedRefresh%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFeedRefresh%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFeedRefresh%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedRefresh%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFeedRefresh%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedRefresh%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedRefresh%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFeedRefresh(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "POST" {
		s.worker.RefreshFeeds()
		c.Out.WriteHeader(http.StatusOK)
	} else {
		c.Out.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFeedErrors` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFeedErrors`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFeedErrors%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedErrors%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFeedErrors%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedErrors%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedErrors%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFeedErrors%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedErrors%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedErrors%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFeedErrors%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFeedErrors%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFeedErrors%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedErrors%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFeedErrors%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedErrors%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedErrors%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFeedErrors(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	errors := s.db.GetFeedErrors()
	c.JSON(http.StatusOK, errors)
}

type feedicon struct {
	ctype string
	bytes []byte
	etag  string
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFeedIcon` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFeedIcon`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFeedIcon%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedIcon%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFeedIcon%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedIcon%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedIcon%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFeedIcon%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedIcon%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedIcon%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFeedIcon%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFeedIcon%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFeedIcon%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedIcon%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFeedIcon%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedIcon%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedIcon%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFeedIcon(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	id, err := c.VarInt64("id")
	if err != nil {
		c.Out.WriteHeader(http.StatusBadRequest)
		return
	}

	cachekey := "icon:" + strconv.FormatInt(id, 10)
	s.cache_mutex.Lock()
	cachedat := s.cache[cachekey]
	s.cache_mutex.Unlock()
	if cachedat == nil {
		feed := s.db.GetFeed(id)
		if feed == nil || feed.Icon == nil {
			c.Out.WriteHeader(http.StatusNotFound)
			return
		}

		hash := md5.New()
		hash.Write(*feed.Icon)

		etag := fmt.Sprintf("%x", hash.Sum(nil))[:16]

		cachedat = feedicon{
			ctype: http.DetectContentType(*feed.Icon),
			bytes: *(*feed).Icon,
			etag:  etag,
		}
		s.cache_mutex.Lock()
		s.cache[cachekey] = cachedat
		s.cache_mutex.Unlock()
	}

	icon := cachedat.(feedicon)

	if c.Req.Header.Get("If-None-Match") == icon.etag {
		c.Out.WriteHeader(http.StatusNotModified)
		return
	}

	c.Out.Header().Set("Content-Type", icon.ctype)
	c.Out.Header().Set("Etag", icon.etag)
	c.Out.Write(icon.bytes)
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFeedList` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFeedList`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFeedList%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFeedList%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedList%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeedList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFeedList%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeedList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFeedList%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFeedList%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFeedList%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFeedList%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedList%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeedList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFeedList(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "GET" {
		list := s.db.ListFeeds()
		c.JSON(http.StatusOK, list)
	} else if c.Req.Method == "POST" {
		var form FeedCreateForm
		if err := json.NewDecoder(c.Req.Body).Decode(&form); err != nil {
			log.Print(err)
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}

		result, err := worker.DiscoverFeed(form.Url)
		switch {
		case err != nil:
			log.Printf("Faild to discover feed for %s: %s", form.Url, err)
			c.JSON(http.StatusOK, map[string]string{"status": "notfound"})
		case len(result.Sources) > 0:
			c.JSON(http.StatusOK, map[string]interface{}{"status": "multiple", "choice": result.Sources})
		case result.Feed != nil:
			feed := s.db.CreateFeed(
				result.Feed.Title,
				"",
				result.Feed.SiteURL,
				result.FeedLink,
				form.FolderID,
			)
			items := worker.ConvertItems(result.Feed.Items, *feed)
			if len(items) > 0 {
				s.db.CreateItems(items)
				s.db.SetFeedSize(feed.Id, len(items))
				s.db.SyncSearch()
			}
			s.worker.FindFeedFavicon(*feed)

			c.JSON(http.StatusOK, map[string]interface{}{
				"status": "success",
				"feed":   feed,
			})
		default:
			c.JSON(http.StatusOK, map[string]string{"status": "notfound"})
		}
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleFeed` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleFeed`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleFeed%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeed%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleFeed%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeed%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleFeed%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleFeed%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeed%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleFeed%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleFeed%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleFeed%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleFeed%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeed%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleFeed%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeed%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleFeed%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleFeed(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	id, err := c.VarInt64("id")
	if err != nil {
		c.Out.WriteHeader(http.StatusBadRequest)
		return
	}
	if c.Req.Method == "PUT" {
		feed := s.db.GetFeed(id)
		if feed == nil {
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		body := make(map[string]interface{})
		if err := json.NewDecoder(c.Req.Body).Decode(&body); err != nil {
			log.Print(err)
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		if title, ok := body["title"]; ok {
			if reflect.TypeOf(title).Kind() == reflect.String {
				s.db.RenameFeed(id, title.(string))
			}
		}
		if f_id, ok := body["folder_id"]; ok {
			if f_id == nil {
				s.db.UpdateFeedFolder(id, nil)
			} else if reflect.TypeOf(f_id).Kind() == reflect.Float64 {
				folderId := int64(f_id.(float64))
				s.db.UpdateFeedFolder(id, &folderId)
			}
		}
		c.Out.WriteHeader(http.StatusOK)
	} else if c.Req.Method == "DELETE" {
		s.db.DeleteFeed(id)
		c.Out.WriteHeader(http.StatusNoContent)
	} else {
		c.Out.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleItem` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleItem`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleItem%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleItem%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleItem%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleItem%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleItem%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleItem%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleItem%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleItem%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleItem%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleItem%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleItem%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleItem%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleItem%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleItem%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleItem%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleItem(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	id, err := c.VarInt64("id")
	if err != nil {
		c.Out.WriteHeader(http.StatusBadRequest)
		return
	}
	if c.Req.Method == "GET" {
		item := s.db.GetItem(id)
		if item == nil {
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}

		// runtime fix for relative links
		if !htmlutil.IsAPossibleLink(item.Link) {
			if feed := s.db.GetFeed(item.FeedId); feed != nil {
				item.Link = htmlutil.AbsoluteUrl(item.Link, feed.Link)
			}
		}

		item.Content = sanitizer.Sanitize(item.Link, item.Content)

		c.JSON(http.StatusOK, item)
	} else if c.Req.Method == "PUT" {
		var body ItemUpdateForm
		if err := json.NewDecoder(c.Req.Body).Decode(&body); err != nil {
			log.Print(err)
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Status != nil {
			s.db.UpdateItemStatus(id, *body.Status)
		}
		c.Out.WriteHeader(http.StatusOK)
	} else {
		c.Out.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleItemList` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleItemList`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleItemList%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleItemList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleItemList%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleItemList%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleItemList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleItemList%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleItemList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleItemList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleItemList%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleItemList%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleItemList%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleItemList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleItemList%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleItemList%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleItemList%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleItemList(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "GET" {
		perPage := 20
		query := c.Req.URL.Query()

		filter := storage.ItemFilter{}
		if folderID, err := c.QueryInt64("folder_id"); err == nil {
			filter.FolderID = &folderID
		}
		if feedID, err := c.QueryInt64("feed_id"); err == nil {
			filter.FeedID = &feedID
		}
		if after, err := c.QueryInt64("after"); err == nil {
			filter.After = &after
		}
		if status := query.Get("status"); len(status) != 0 {
			statusValue := storage.StatusValues[status]
			filter.Status = &statusValue
		}
		if search := query.Get("search"); len(search) != 0 {
			filter.Search = &search
		}
		newestFirst := query.Get("oldest_first") != "true"

		items := s.db.ListItems(filter, perPage+1, newestFirst, false)
		hasMore := false
		if len(items) == perPage+1 {
			hasMore = true
			items = items[:perPage]
		}
		c.JSON(http.StatusOK, map[string]interface{}{
			"list":     items,
			"has_more": hasMore,
		})
	} else if c.Req.Method == "PUT" {
		filter := storage.MarkFilter{}

		if folderID, err := c.QueryInt64("folder_id"); err == nil {
			filter.FolderID = &folderID
		}
		if feedID, err := c.QueryInt64("feed_id"); err == nil {
			filter.FeedID = &feedID
		}
		s.db.MarkItemsRead(filter)
		c.Out.WriteHeader(http.StatusOK)
	} else {
		c.Out.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleSettings` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleSettings`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleSettings%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleSettings%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleSettings%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleSettings%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleSettings%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleSettings%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleSettings%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleSettings%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleSettings%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleSettings%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleSettings%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleSettings%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleSettings%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleSettings%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleSettings%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "API" --latency-target 99 --latency-ms 5
func (s *Server) handleSettings(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("API"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "GET" {
		c.JSON(http.StatusOK, s.db.GetSettings())
	} else if c.Req.Method == "PUT" {
		settings := make(map[string]interface{})
		if err := json.NewDecoder(c.Req.Body).Decode(&settings); err != nil {
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		if s.db.UpdateSettings(settings) {
			if _, ok := settings["refresh_rate"]; ok {
				s.worker.SetRefreshRate(s.db.GetSettingsValueInt64("refresh_rate"))
			}
			c.Out.WriteHeader(http.StatusOK)
		} else {
			c.Out.WriteHeader(http.StatusBadRequest)
		}
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleOPMLImport` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleOPMLImport`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleOPMLImport%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleOPMLImport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleOPMLImport%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleOPMLImport%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleOPMLImport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleOPMLImport%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleOPMLImport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleOPMLImport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleOPMLImport%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleOPMLImport%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleOPMLImport%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleOPMLImport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleOPMLImport%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleOPMLImport%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleOPMLImport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "OPML" --latency-target 99 --latency-ms 5
func (s *Server) handleOPMLImport(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("OPML"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "POST" {
		file, _, err := c.Req.FormFile("opml")
		if err != nil {
			log.Print(err)
			return
		}
		doc, err := opml.Parse(file)
		if err != nil {
			log.Print(err)
			c.Out.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, f := range doc.Feeds {
			s.db.CreateFeed(f.Title, "", f.SiteUrl, f.FeedUrl, nil)
		}
		for _, f := range doc.Folders {
			folder := s.db.CreateFolder(f.Title)
			for _, ff := range f.AllFeeds() {
				s.db.CreateFeed(ff.Title, "", ff.SiteUrl, ff.FeedUrl, &folder.Id)
			}
		}

		s.worker.FindFavicons()
		s.worker.RefreshFeeds()

		c.Out.WriteHeader(http.StatusOK)
	} else {
		c.Out.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleOPMLExport` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleOPMLExport`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleOPMLExport%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleOPMLExport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleOPMLExport%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleOPMLExport%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleOPMLExport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleOPMLExport%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleOPMLExport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleOPMLExport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleOPMLExport%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleOPMLExport%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleOPMLExport%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleOPMLExport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleOPMLExport%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleOPMLExport%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleOPMLExport%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc --slo "OPML" --latency-target 99 --latency-ms 5
func (s *Server) handleOPMLExport(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
		autometrics.WithSloName("OPML"),
		autometrics.WithAlertLatency(5000000*time.Nanosecond, 99),
	)), nil) //autometrics:defer

	if c.Req.Method == "GET" {
		c.Out.Header().Set("Content-Type", "application/xml; charset=utf-8")
		c.Out.Header().Set("Content-Disposition", `attachment; filename="subscriptions.opml"`)

		doc := opml.Folder{}

		feedsByFolderID := make(map[int64][]*storage.Feed)
		for _, feed := range s.db.ListFeeds() {
			feed := feed
			if feed.FolderId == nil {
				doc.Feeds = append(doc.Feeds, opml.Feed{
					Title:   feed.Title,
					FeedUrl: feed.FeedLink,
					SiteUrl: feed.Link,
				})
			} else {
				id := *feed.FolderId
				feedsByFolderID[id] = append(feedsByFolderID[id], &feed)
			}
		}

		for _, folder := range s.db.ListFolders() {
			folderFeeds := feedsByFolderID[folder.Id]
			if len(folderFeeds) == 0 {
				continue
			}
			opmlfolder := opml.Folder{Title: folder.Title}
			for _, feed := range folderFeeds {
				opmlfolder.Feeds = append(opmlfolder.Feeds, opml.Feed{
					Title:   feed.Title,
					FeedUrl: feed.FeedLink,
					SiteUrl: feed.Link,
				})
			}
			doc.Folders = append(doc.Folders, opmlfolder)
		}

		c.Out.Write([]byte(doc.OPML()))
	}
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handlePageCrawl` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handlePageCrawl`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handlePageCrawl%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handlePageCrawl%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handlePageCrawl%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handlePageCrawl%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handlePageCrawl%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handlePageCrawl%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handlePageCrawl%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handlePageCrawl%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handlePageCrawl%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handlePageCrawl%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handlePageCrawl%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handlePageCrawl%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handlePageCrawl%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handlePageCrawl%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handlePageCrawl%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:doc
func (s *Server) handlePageCrawl(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
	)), nil) //autometrics:defer

	url := c.Req.URL.Query().Get("url")

	if newUrl := silo.RedirectURL(url); newUrl != "" {
		url = newUrl
	}
	if content := silo.VideoIFrame(url); content != "" {
		c.JSON(http.StatusOK, map[string]string{
			"content": sanitizer.Sanitize(url, content),
		})
		return
	}

	body, err := worker.GetBody(url)
	if err != nil {
		log.Print(err)
		c.Out.WriteHeader(http.StatusBadRequest)
		return
	}
	content, err := readability.ExtractContent(strings.NewReader(body))
	if err != nil {
		c.JSON(http.StatusOK, map[string]string{
			"content": "error: " + err.Error(),
		})
		return
	}
	content = sanitizer.Sanitize(url, content)
	c.JSON(http.StatusOK, map[string]string{
		"content": content,
	})
}

//	autometrics:doc-start Generated documentation by Autometrics.
//
// # Autometrics
//
// # Prometheus
//
// View the live metrics for the `handleLogout` function:
//   - [Request Rate]
//   - [Error Ratio]
//   - [Latency (95th and 99th percentiles)]
//   - [Concurrent Calls]
//
// Or, dig into the metrics of *functions called by* `handleLogout`
//   - [Request Rate Callee]
//   - [Error Ratio Callee]
//
//	autometrics:doc-end Generated documentation by Autometrics.
//
// [Request Rate]: http://localhost:9090/graph?g0.expr=%23+Rate+of+calls+to+the+%60handleLogout%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleLogout%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+calls+to+the+%60handleLogout%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleLogout%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bfunction%3D%22handleLogout%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
// [Latency (95th and 99th percentiles)]: http://localhost:9090/graph?g0.expr=%23+95th+and+99th+percentile+latencies+%28in+seconds%29+for+the+%60handleLogout%60+function%0A%0Alabel_replace%28histogram_quantile%280.99%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleLogout%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C+%22percentile_latency%22%2C+%2299%22%2C+%22%22%2C+%22%22%29+or+label_replace%28histogram_quantile%280.95%2C+sum+by+%28le%2C+function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_duration_seconds_bucket%7Bfunction%3D%22handleLogout%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29%2C%22percentile_latency%22%2C+%2295%22%2C+%22%22%2C+%22%22%29&g0.tab=0
// [Concurrent Calls]: http://localhost:9090/graph?g0.expr=%23+Concurrent+calls+to+the+%60handleLogout%60+function%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28function_calls_concurrent%7Bfunction%3D%22handleLogout%22%7D+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Request Rate Callee]: http://localhost:9090/graph?g0.expr=%23+Rate+of+function+calls+emanating+from+%60handleLogout%60+function+per+second%2C+averaged+over+5+minute+windows%0A%0Asum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleLogout%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29&g0.tab=0
// [Error Ratio Callee]: http://localhost:9090/graph?g0.expr=%23+Percentage+of+function+emanating+from+%60handleLogout%60+function+that+return+errors%2C+averaged+over+5+minute+windows%0A%0A%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleLogout%22%2Cresult%3D%22error%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29+%2F+%28sum+by+%28function%2C+module%2C+service_name%2C+version%2C+commit%29+%28rate%28function_calls_total%7Bcaller_function%3D%22handleLogout%22%7D%5B5m%5D%29+%2A+on+%28instance%2C+job%29+group_left%28version%2C+commit%29+last_over_time%28build_info%5B1s%5D%29%29%29&g0.tab=0
//
//autometrics:inst
func (s *Server) handleLogout(c *router.Context) {
	defer autometrics.Instrument(autometrics.PreInstrument(autometrics.NewContext(
		nil,
		autometrics.WithConcurrentCalls(true),
		autometrics.WithCallerName(true),
	)), nil) //autometrics:defer

	auth.Logout(c.Out, s.BasePath)
	c.Out.WriteHeader(http.StatusNoContent)
}
