const jwt = require("jsonwebtoken");

/**
 * Authentication middleware for API Gateway
 * Verifies JWT tokens before proxying requests to microservices
 */

/**
 * Routes that don't require authentication
 */
const PUBLIC_ROUTES = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/health',
  '/api'
];

/**
 * Check if a route is public (doesn't require authentication)
 * @param {string} path - Request path
 * @returns {boolean}
 */
function isPublicRoute(path) {
  return PUBLIC_ROUTES.some(route => {
    if (route.includes('*')) {
      const baseRoute = route.replace('/*', '');
      return path.startsWith(baseRoute);
    }
    return path === route || path.startsWith(route);
  });
}

/**
 * Middleware to verify JWT tokens at gateway level
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
function gatewayAuthMiddleware(req, res, next) {
  // Skip authentication for public routes
  if (isPublicRoute(req.path)) {
    return next();
  }

  try {
    const authHeader = req.headers?.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
        timestamp: new Date().toISOString()
      });
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({
        success: false,
        message: "Invalid authorization header format",
        timestamp: new Date().toISOString()
      });
    }

    const token = parts[1];
    const jwtSecret = process.env.JWT_SECRET;
    
    if (!jwtSecret) {
      console.error("JWT_SECRET not configured in gateway");
      return res.status(500).json({
        success: false,
        message: "Server configuration error",
        timestamp: new Date().toISOString()
      });
    }

    // Verify token
    const decoded = jwt.verify(token, jwtSecret);
    
    // Add user information to headers for downstream services
    req.headers['x-user-id'] = decoded.user?.id || decoded.user?._id;
    req.headers['x-user-email'] = decoded.user?.email;
    req.headers['x-user-type'] = decoded.user?.userType;
    req.headers['x-user-data'] = JSON.stringify(decoded.user);
    
    console.log(`Gateway: Authenticated user ${decoded.user?.email}`);
    next();
    
  } catch (error) {
    console.error("Gateway authentication error:", error.message);
    
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Token has expired",
        timestamp: new Date().toISOString()
      });
    }
    
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token",
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Middleware to extract user info from gateway headers (for downstream services)
 * Use this in your microservices instead of JWT verification
 */
function extractUserFromGateway(req, res, next) {
  try {
    // Extract user information from headers set by gateway
    if (req.headers['x-user-data']) {
      req.user = JSON.parse(req.headers['x-user-data']);
      req.userId = req.headers['x-user-id'];
      req.userEmail = req.headers['x-user-email'];
      req.userType = req.headers['x-user-type'];
    }
    
    next();
  } catch (error) {
    console.error("Error extracting user from gateway headers:", error);
    next(); // Continue without user data
  }
}

module.exports = {
  gatewayAuthMiddleware,
  extractUserFromGateway,
  isPublicRoute
};
