require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const { createProxyMiddleware } = require("http-proxy-middleware");
const proxy = require("express-http-proxy");
const winston = require("winston");
const { gatewayAuthMiddleware } = require("./middleware/auth.middleware");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const http = require("http");

const app = express();
const PORT = process.env.PORT || 3000;

// Enable trust proxy - required for rate limiting behind reverse proxies
app.set("trust proxy", 1);

/**
 * Setup Winston logger
 */
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  defaultMeta: { service: "api-gateway" },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
      ),
    }),
    new winston.transports.File({ filename: "logs/gateway.log" }),
  ],
});

/**
 * Setup middleware
 */

// Enable CORS
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    optionsSuccessStatus: 200,
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    allowedHeaders:
      "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-access-token",
    credentials: true,
  }),
);

// Enable JSON parsing
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] API Gateway | ${req.method} ${req.originalUrl}`);
  next();
});

// Security middleware
app.use(helmet());

// Compression
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    success: false,
    message: "Too many requests from this IP, please try again later",
    timestamp: new Date().toISOString(),
  },
});
app.use(limiter);

// Body parsing middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));
app.use(cookieParser());

// Raw body parsing for file uploads
app.use((req, res, next) => {
  if (
    req.headers["content-type"] &&
    req.headers["content-type"].includes("multipart/form-data")
  ) {
    return next();
  }
  bodyParser.raw({ type: "*/*", limit: "50mb" })(req, res, next);
});

// Request timeout middleware
app.use((req, res, next) => {
  // Set timeout for all requests
  req.setTimeout(30000, () => {
    logger.warn(`Request timeout: ${req.method} ${req.path}`);
    if (!res.headersSent) {
      res.status(408).json({
        success: false,
        message: "Request timeout",
        timestamp: new Date().toISOString(),
      });
    }
  });

  next();
});

// Service URLs (get from environment variables)
const AUTH_SERVICE_URL =
  process.env.AUTH_SERVICE_URL || "http://localhost:3001";
const IAM_SERVICE_URL = process.env.IAM_SERVICE_URL || "http://localhost:3002";
const INVENTORY_SERVICE_URL =
  process.env.INVENTORY_SERVICE_URL || "http://localhost:3003";

console.log(`Using AUTH_SERVICE_URL: ${AUTH_SERVICE_URL}`);
console.log(`Using INVENTORY_SERVICE_URL: ${INVENTORY_SERVICE_URL}`);
console.log(`Using IAM_SERVICE_URL: ${IAM_SERVICE_URL}`);

/**
 * Setup service routes and proxies
 */
// Health check endpoint for the gateway itself
app.get("/gateway/health", (req, res) => {
  res.json({
    status: "ok",
    service: "api-gateway",
    timestamp: new Date().toISOString(),
    services: {
      auth: AUTH_SERVICE_URL,
      order: INVENTORY_SERVICE_URL,
      kyc: KYC_SERVICE_URL,
    },
  });
});

// Proxy middleware for auth service
app.use(
  "/api/authz",
  proxy(AUTH_SERVICE_URL, {
    proxyReqPathResolver: function (req) {
      // Convert /register to /api/register for auth service
      const originalPath = req.url;
      const newPath = "/api/authz" + originalPath;
      const timestamp = new Date().toISOString();
      console.log(
        `[${timestamp}] API Gateway | Proxying to Auth Service: ${originalPath} -> ${newPath}`,
      );
      return newPath;
    },
    userResDecorator: function (proxyRes, proxyResData, userReq, userRes) {
      const timestamp = new Date().toISOString();
      console.log(
        `[${timestamp}] API Gateway | Auth Service Response: ${proxyRes.statusCode}`,
      );
      return proxyResData;
    },
    proxyErrorHandler: function (err, res, next) {
      console.error("[Auth Service Proxy Error]:", err);
      if (!res.headersSent) {
        res.status(500).json({
          status: "error",
          message: "Auth service unavailable",
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      }
    },
  }),
);

// Proxy middleware for iam service
app.use(
  "/api/iam",
  proxy(IAM_SERVICE_URL, {
    proxyReqPathResolver: function (req) {
      // Convert /register to /api/register for auth service
      const originalPath = req.url;
      const newPath = "/api/iam" + originalPath;
      const timestamp = new Date().toISOString();
      console.log(
        `[${timestamp}] API Gateway | Proxying to Auth Service: ${originalPath} -> ${newPath}`,
      );
      return newPath;
    },
    userResDecorator: function (proxyRes, proxyResData, userReq, userRes) {
      const timestamp = new Date().toISOString();
      console.log(
        `[${timestamp}] API Gateway | IAM Service Response: ${proxyRes.statusCode}`,
      );
      return proxyResData;
    },
    proxyErrorHandler: function (err, res, next) {
      console.error("[IAM Service Proxy Error]:", err);
      if (!res.headersSent) {
        res.status(500).json({
          status: "error",
          message: "IAM service unavailable",
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      }
    },
  }),
);

// Proxy middleware for inventory service
app.use(
  "/api/inv",
  proxy(INVENTORY_SERVICE_URL, {
    proxyReqPathResolver: function (req) {
      // Convert /register to /api/register for auth service
      const originalPath = req.url;
      const newPath = "/api/inv" + originalPath;
      const timestamp = new Date().toISOString();
      console.log(
        `[${timestamp}] API Gateway | Proxying to Inventory Service: ${originalPath} -> ${newPath}`,
      );
      return newPath;
    },
    userResDecorator: function (proxyRes, proxyResData, userReq, userRes) {
      const timestamp = new Date().toISOString();
      console.log(
        `[${timestamp}] API Gateway | Inventory Service Response: ${proxyRes.statusCode}`,
      );
      return proxyResData;
    },
    proxyErrorHandler: function (err, res, next) {
      console.error("[Inventory Service Proxy Error]:", err);
      if (!res.headersSent) {
        res.status(500).json({
          status: "error",
          message: "Inventory service unavailable",
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      }
    },
  }),
);

// API documentation
app.get("/api", (req, res) => {
  res.status(200).json({
    success: true,
    message: "ics API Gateway",
    version: "1.0.0",
    services: ["auth-service", "kyc-service", "order-service"],
    endpoints: {
      authz: "/api/authz/*",
      iam: "/api/iam/*",
      inventory: "/api/inventory/*",
    },
    documentation: "https://docs.ics.com",
    timestamp: new Date().toISOString(),
  });
});

/**
 * Setup error handling
 */
// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
    timestamp: new Date().toISOString(),
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Gateway Error:", err);
  if (!res.headersSent) {
    res.status(err.status || 500).json({
      status: "error",
      message: err.message || "Internal Server Error",
      timestamp: new Date().toISOString(),
    });
  }
});

// Create HTTP server for WebSocket support
const server = http.createServer(app);

server.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
  console.log(`Proxying /api/authz to ${AUTH_SERVICE_URL}`);
  console.log(`Proxying /api/iam to ${IAM_SERVICE_URL}`);
  console.log(`Proxying /api/inventory to ${INVENTORY_SERVICE_URL}`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  server.close(() => {
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully");
  server.close(() => {
    process.exit(0);
  });
});
