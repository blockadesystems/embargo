package server

import (
	"net/http"
	"os"
	"strconv"

	"github.com/blockadesystems/embargo/internal/kvengine"
	"github.com/blockadesystems/embargo/internal/shared"
	"github.com/blockadesystems/embargo/internal/storage"
	"github.com/blockadesystems/embargo/internal/sys"
	"github.com/blockadesystems/embargo/internal/tokenauth"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func checkInitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	db := storage.GetStore()
	return func(c echo.Context) error {
		initialized := false
		i, err := db.ReadKey("embargo_sys", "initialized", false)
		if err != nil {
			return c.JSON(http.StatusPreconditionFailed, "system not initialized")
		}
		initialized, _ = strconv.ParseBool(string(i))
		if !initialized {
			initReturn := make(map[string]interface{})
			initReturn["status"] = "system not initialized"
			return c.JSON(http.StatusPreconditionFailed, initReturn)
		}
		return next(c)
	}
}

func checkSealMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	sealed := sys.SealStatus()
	if sealed {
		return func(c echo.Context) error {
			return c.JSON(http.StatusPreconditionFailed, "system sealed")
		}
	}
	return next
}

func createLogger(logLevel string) *zap.Logger {
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	newLogLevel := zap.InfoLevel
	switch logLevel {
	case "debug":
		newLogLevel = zap.DebugLevel
	case "info":
		newLogLevel = zap.InfoLevel
	case "warn":
		newLogLevel = zap.WarnLevel
	case "error":
		newLogLevel = zap.ErrorLevel
	case "fatal":
		newLogLevel = zap.FatalLevel
	case "panic":
		newLogLevel = zap.PanicLevel
	}

	config := zap.Config{
		Level:             zap.NewAtomicLevelAt(newLogLevel),
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          "json",
		EncoderConfig:     encoderCfg,
		OutputPaths: []string{
			"stderr",
		},
		ErrorOutputPaths: []string{
			"stderr",
		},
		InitialFields: map[string]interface{}{
			"pid": os.Getpid(),
		},
	}

	return zap.Must(config.Build())
}

func StartServer(devMode bool) {
	// Set up logger
	logLevel := os.Getenv("EMBARGO_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	logger := createLogger(logLevel)
	defer logger.Sync()
	logger.Info("Starting Embargo")

	// Get the storage type from the environment
	storageType := os.Getenv("EMBARGO_STORAGE_TYPE")
	if storageType == "" {
		storageType = "memory"
	}

	// iIf devMode is true, configure Embargo to run in development mode
	if devMode {
		storageType = "memory"
		logger.Info("Running in development mode")
		os.Setenv("EMBARGO_FILE", "embargodev.db")
		os.Setenv("EMBARGO_TLS_DISABLE", "true")

		// Remove the database file if it exists
		if _, err := os.Stat("embargodev.db"); err == nil {
			logger.Info("Removing existing database file")
			err := os.Remove("embargodev.db")
			if err != nil {
				logger.Error("error removing database file", zap.Error(err))
			}
		}

		storage.InitDB(storageType)
		sys.StartSys()
		var r shared.InitSysRequest
		r.Shares = 2
		r.Threshold = 2
		res, err := sys.InitSys(r)
		if err != nil {
			logger.Error("error initializing system", zap.Error(err))
		}

		// set EMBARGO_AUTO_UNSEAL to true and set the unseal keys
		os.Setenv("EMBARGO_AUTO_UNSEAL", "true")
		os.Setenv("EMBARGO_UNSEAL_KEYS", res.Shares[0]+","+res.Shares[1])

		sys.StartSys()

		message := `Embargo is running in development mode.
		The database file is embargodev.db and will be removed the next time you start Embargo in dev mode.
		To access the server, use the following token: ` + res.RootToken
		println(message)
	} else {
		storage.InitDB(storageType)
		sys.StartSys()
	}

	e := echo.New()
	e.HideBanner = true

	newBanner := `
	+-+-+-+-+-+-+-+
	|E|m|b|a|r|g|o|
	+-+-+-+-+-+-+-+`

	println(newBanner)

	e.Use(middleware.Recover())

	// Logger middleware
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:    true,
		LogStatus: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logger.Info("request",
				zap.String("URI", v.URI),
				zap.Int("status", v.Status),
			)

			return nil
		},
	}))
	// create middleware to pass logger to handlers
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("logger", logger)
			return next(c)
		}
	})

	// Middleware, skip if init
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		initMiddleware := checkInitMiddleware(next)
		return func(c echo.Context) error {
			if c.Path() == "/sys/init" {
				return next(c)
			}
			return initMiddleware(c)
		}
	})
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		sealMiddleware := checkSealMiddleware(next)
		return func(c echo.Context) error {
			if c.Path() == "/sys/init" || c.Path() == "/sys/unseal" || c.Path() == "/sys/seal-status" {
				return next(c)
			}
			return sealMiddleware(c)
		}
	})
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Server Running")
	})

	e.GET("/sys/init", sys.InitStatus)
	e.POST("/sys/init", sys.InitSysPost)
	e.GET("/sys/seal-status", sys.GetSealStatus)
	e.POST("/sys/unseal", sys.Unseal)

	// Calls below this line require a valid token
	skipPaths := []string{"/sys/init", "/sys/seal-status", "/sys/unseal"}
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		embargoTokenMiddleware := tokenauth.ValidateEmbargoToken(next)
		return func(c echo.Context) error {
			for _, path := range skipPaths {
				if c.Path() == path {
					return next(c)
				}
			}
			return embargoTokenMiddleware(c)
		}
	})

	// System endpoints
	e.GET("/sys/mounts", sys.Get_mounts)
	e.GET("/sys/mounts/:mount", sys.GetMount)
	e.POST("/sys/mounts/:mount", sys.CreateMount)
	e.GET("/sys/mounts/:mount/tune", sys.GetMountTune)
	e.POST("/sys/mounts/:mount/tune", sys.PostMountTune)
	e.GET("/sys/rekey/init", sys.RekeyInitGet)
	e.POST("/sys/rekey/init", sys.RekeyInitPost)
	e.DELETE("/sys/rekey/init", sys.RekeyInitDelete)
	e.POST("/sys/rekey/update", sys.RekeyUpdatePost)
	// e.PUT("/sys/mounts/:mount", kvengine.Update_mount)
	// e.DELETE("/sys/mounts/:mount", kvengine.Delete_mount)
	// e.POST("/sys/rotate", kvengine.RotateKey)

	// KV Engine
	e.Add("LIST", "/kv/:mount/metadata/:path", kvengine.ListMetadata)
	// e.GET("/kv/:mount/config/:path", kvengine.GetKVConfig)
	// e.POST("/kv/:mount/config", kvengine.PostVConfig)
	e.GET("/kv/:mount/data/:path", kvengine.GetKV)
	e.POST("/kv/:mount/data/:path", kvengine.PostKV)
	// e.PUT("/kv/:mount/:path", kvengine.PutKV)
	e.DELETE("/kv/:mount/data/:path", kvengine.DeleteKV)
	e.POST("/kv/:mount/delete/:path", kvengine.DeleteKV)
	e.POST("/kv/:mount/undelete/:path", kvengine.UndeleteKV)
	e.POST("/kv/:mount/destroy/:path", kvengine.DestroyKV)

	// auth endpoints
	e.POST("/auth/token", tokenauth.CreateToken)
	e.POST("/auth/token/renew", tokenauth.RenewToken)
	e.POST("/auth/policies", tokenauth.CreatePolicy)
	e.GET("/auth/policies", tokenauth.GetPolicies)
	e.GET("/auth/policies/:policy", tokenauth.GetPolicy)
	e.DELETE("/auth/policies/:policy", tokenauth.DeletePolicy)

	// Get address and port from config
	address := os.Getenv("EMBARGO_ADDRESS")
	port := os.Getenv("EMBARGO_PORT")

	if port == "" {
		port = "8080"
	}

	tlsDisableTxt := os.Getenv("EMBARGO_TLS_DISABLE")
	if tlsDisableTxt == "" {
		tlsDisableTxt = "false"
	}
	tlsDisable, _ := strconv.ParseBool(tlsDisableTxt)

	if tlsDisable {
		tlsWarning := "WARNING: EMBARGO_TLS_DISABLED is set to true. This is not recommended for production use."
		println(tlsWarning)
		e.Logger.Fatal(e.Start(address + ":" + port))
	} else {
		crtFile := os.Getenv("EMBARGO_TLS_CERT_FILE")
		keyFile := os.Getenv("EMBARGO_TLS_KEY_FILE")
		if crtFile == "" || keyFile == "" {
			logger.Fatal("EMBARGO_TLS_CERT_FILE and EMBARGO_TLS_KEY_FILE must be set if EMBARGO_TLS_DISABLED is false")
		} else {
			e.Logger.Fatal(e.StartTLS(address+":"+port, crtFile, keyFile))
		}
	}

}
