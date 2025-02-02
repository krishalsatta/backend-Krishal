const express = require('express');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const xss = require('xss-clean');

const securityMiddleware = express.Router();

securityMiddleware.use(helmet());

// Prevent XSS attacks
securityMiddleware.use(xss());

// Prevent HTTP Parameter Pollution
securityMiddleware.use(hpp());

// Rate limiting
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 100, 
});
securityMiddleware.use('/api', limiter);

securityMiddleware.use(mongoSanitize());

module.exports = securityMiddleware;
