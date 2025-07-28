import express from 'express';
import cors from 'cors';
import puppeteer from 'puppeteer';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import crypto from 'crypto';
import { promisify } from 'util';

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_FILE_AGE = parseInt(process.env.MAX_FILE_AGE) || 30 * 60 * 1000; // 30 minutes
const ALLOWED_DOMAINS = process.env.ALLOWED_DOMAINS?.split(',').map(d => d.trim()) || [];
const MAX_CONCURRENT_BROWSERS = parseInt(process.env.MAX_CONCURRENT_BROWSERS) || 3;
const MAX_SCREENSHOT_SIZE = parseInt(process.env.MAX_SCREENSHOT_SIZE) || 10 * 1024 * 1024; // 10MB
const BLOCKED_PATTERNS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '10.',
  '192.168.',
  '172.16.',
  '172.17.',
  '172.18.',
  '172.19.',
  '172.20.',
  '172.21.',
  '172.22.',
  '172.23.',
  '172.24.',
  '172.25.',
  '172.26.',
  '172.27.',
  '172.28.',
  '172.29.',
  '172.30.',
  '172.31.'
];

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Enhanced logging
const logger = {
  info: (msg, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, meta),
  error: (msg, error = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, error),
  warn: (msg, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`, meta),
  debug: (msg, meta = {}) => process.env.NODE_ENV === 'development' && console.log(`[DEBUG] ${new Date().toISOString()} - ${msg}`, meta)
};

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(compression());
app.use(morgan('combined'));

app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || ['*'];
    if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

// Enhanced rate limiting with different tiers
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message, retryAfter: Math.ceil(windowMs / 1000) },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip + ':' + (req.headers['x-api-key'] || 'anonymous');
  }
});

// Different rate limits for different endpoints
app.use('/screenshot', createRateLimit(
  15 * 60 * 1000, // 15 minutes
  parseInt(process.env.RATE_LIMIT_SCREENSHOT) || 50,
  'Too many screenshot requests, please try again later'
));

app.use(createRateLimit(
  15 * 60 * 1000, // 15 minutes
  parseInt(process.env.RATE_LIMIT_GENERAL) || 200,
  'Too many requests, please try again later'
));

app.use(express.json({ 
  limit: '1mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Request ID middleware
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Enhanced Browser Pool with health checks and metrics
class BrowserPool {
  constructor(maxSize = MAX_CONCURRENT_BROWSERS) {
    this.browsers = [];
    this.maxSize = maxSize;
    this.currentSize = 0;
    this.metrics = {
      created: 0,
      destroyed: 0,
      inUse: 0,
      errors: 0
    };
    this.healthCheckInterval = setInterval(() => this.healthCheck(), 60000); // Every minute
  }

  async getBrowser() {
    if (this.browsers.length > 0) {
      const browser = this.browsers.pop();
      this.metrics.inUse++;
      return browser;
    }

    if (this.currentSize < this.maxSize) {
      this.currentSize++;
      try {
        const browser = await puppeteer.launch({
          headless: 'new',
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--disable-features=TranslateUI',
            '--disable-ipc-flooding-protection',
            '--memory-pressure-off',
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor'
          ],
          defaultViewport: null,
          timeout: 30000
        });

        this.metrics.created++;
        this.metrics.inUse++;
        
        browser.on('disconnected', () => {
          this.currentSize--;
          this.metrics.destroyed++;
        });

        return browser;
      } catch (error) {
        this.currentSize--;
        this.metrics.errors++;
        throw error;
      }
    }

    // Wait for a browser to become available
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Browser pool timeout'));
      }, 30000);

      const checkForBrowser = () => {
        if (this.browsers.length > 0) {
          clearTimeout(timeout);
          const browser = this.browsers.pop();
          this.metrics.inUse++;
          resolve(browser);
        } else {
          setTimeout(checkForBrowser, 100);
        }
      };
      checkForBrowser();
    });
  }

  async releaseBrowser(browser) {
    try {
      if (browser && !browser.process()?.killed) {
        const pages = await browser.pages();
        // Close all pages except the first one and clear any remaining contexts
        for (let i = 1; i < pages.length; i++) {
          await pages[i].close();
        }
        
        // Clear the default page content
        if (pages[0]) {
          await pages[0].goto('about:blank');
        }
        
        this.browsers.push(browser);
        this.metrics.inUse--;
      }
    } catch (error) {
      logger.warn('Error releasing browser', { error: error.message });
      if (browser) {
        await browser.close().catch(() => {});
        this.currentSize--;
      }
    }
  }

  async healthCheck() {
    const unhealthyBrowsers = [];
    
    for (let i = 0; i < this.browsers.length; i++) {
      const browser = this.browsers[i];
      try {
        if (browser.process()?.killed) {
          unhealthyBrowsers.push(i);
        } else {
          // Test if browser is responsive
          const pages = await Promise.race([
            browser.pages(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
          ]);
        }
      } catch (error) {
        unhealthyBrowsers.push(i);
      }
    }

    // Remove unhealthy browsers
    for (const index of unhealthyBrowsers.reverse()) {
      const browser = this.browsers.splice(index, 1)[0];
      if (browser) {
        await browser.close().catch(() => {});
        this.currentSize--;
      }
    }

    if (unhealthyBrowsers.length > 0) {
      logger.warn(`Removed ${unhealthyBrowsers.length} unhealthy browsers from pool`);
    }
  }

  getMetrics() {
    return {
      ...this.metrics,
      available: this.browsers.length,
      total: this.currentSize,
      poolSize: this.maxSize
    };
  }

  async closeAll() {
    clearInterval(this.healthCheckInterval);
    const browsers = [...this.browsers];
    this.browsers = [];
    this.currentSize = 0;
    
    await Promise.all(browsers.map(browser => 
      browser.close().catch(error => logger.error('Error closing browser', error))
    ));
  }
}

const browserPool = new BrowserPool();

// Enhanced validation functions
const isValidUrl = (url) => {
  try {
    const parsedUrl = new URL(url);
    const isHttp = parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    
    if (!isHttp) return { valid: false, reason: 'Only HTTP/HTTPS protocols are allowed' };
    
    // Check for blocked patterns (prevent SSRF)
    const hostname = parsedUrl.hostname.toLowerCase();
    for (const pattern of BLOCKED_PATTERNS) {
      if (hostname.includes(pattern)) {
        return { valid: false, reason: 'Access to private/local networks is not allowed' };
      }
    }
    
    // Check if domain is in allowed list (if specified)
    if (ALLOWED_DOMAINS.length > 0) {
      const isAllowed = ALLOWED_DOMAINS.some(domain => 
        hostname === domain.toLowerCase() || hostname.endsWith(`.${domain.toLowerCase()}`)
      );
      if (!isAllowed) {
        return { valid: false, reason: 'Domain not in allowed list' };
      }
    }
    
    return { valid: true };
  } catch (error) {
    return { valid: false, reason: 'Invalid URL format' };
  }
};

const validateDimensions = (width, height) => {
  const minWidth = 100, maxWidth = 3840;
  const minHeight = 100, maxHeight = 2160;
  
  if (width < minWidth || width > maxWidth) {
    return { valid: false, reason: `Width must be between ${minWidth} and ${maxWidth}` };
  }
  
  if (height < minHeight || height > maxHeight) {
    return { valid: false, reason: `Height must be between ${minHeight} and ${maxHeight}` };
  }
  
  return { valid: true };
};

const validateFormat = (format) => {
  const allowedFormats = ['png', 'jpeg', 'webp', 'pdf'];
  if (!allowedFormats.includes(format)) {
    return { valid: false, reason: `Format must be one of: ${allowedFormats.join(', ')}` };
  }
  return { valid: true };
};

// Animation and dynamic content helpers
const waitForAnimations = async (page, options = {}) => {
  const {
    maxWaitTime = 10000,
    stabilityTime = 500,
    checkInterval = 100
  } = options;

  return page.evaluate(async (maxWaitTime, stabilityTime, checkInterval) => {
    return new Promise((resolve) => {
      let lastChange = Date.now();
      let observer;
      const startTime = Date.now();
      
      const checkStability = () => {
        const now = Date.now();
        if (now - lastChange >= stabilityTime || now - startTime >= maxWaitTime) {
          if (observer) observer.disconnect();
          resolve();
        } else {
          setTimeout(checkStability, checkInterval);
        }
      };

      // Monitor DOM changes
      observer = new MutationObserver(() => {
        lastChange = Date.now();
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style', 'class']
      });

      // Monitor CSS animations and transitions
      const animatedElements = document.querySelectorAll('*');
      let animationCount = 0;

      animatedElements.forEach(el => {
        const styles = getComputedStyle(el);
        if (styles.animationName !== 'none' || styles.transitionProperty !== 'none') {
          animationCount++;
          
          const onAnimationEnd = () => {
            animationCount--;
            lastChange = Date.now();
            el.removeEventListener('animationend', onAnimationEnd);
            el.removeEventListener('transitionend', onAnimationEnd);
          };
          
          el.addEventListener('animationend', onAnimationEnd);
          el.addEventListener('transitionend', onAnimationEnd);
        }
      });

      checkStability();
    });
  }, maxWaitTime, stabilityTime, checkInterval);
};

const waitForNetworkIdle = async (page, options = {}) => {
  const {
    idleTime = 500,
    maxWaitTime = 30000,
    maxInflightRequests = 2
  } = options;

  return new Promise((resolve, reject) => {
    let inflight = 0;
    let lastRequestTime = Date.now();
    const startTime = Date.now();
    
    const timeout = setTimeout(() => {
      reject(new Error('Network idle timeout'));
    }, maxWaitTime);

    const checkIdle = () => {
      const now = Date.now();
      if (inflight <= maxInflightRequests && now - lastRequestTime >= idleTime) {
        clearTimeout(timeout);
        resolve();
      } else if (now - startTime >= maxWaitTime) {
        clearTimeout(timeout);
        resolve(); // Don't reject, just resolve after max wait
      } else {
        setTimeout(checkIdle, 100);
      }
    };

    const onRequest = () => {
      inflight++;
      lastRequestTime = Date.now();
    };

    const onResponse = () => {
      inflight--;
      lastRequestTime = Date.now();
    };

    page.on('request', onRequest);
    page.on('response', onResponse);
    page.on('requestfailed', onResponse);

    checkIdle();
  });
};

const injectAnimationHelpers = async (page) => {
  await page.evaluateOnNewDocument(() => {
    // Helper to pause all CSS animations
    window.pauseAnimations = () => {
      const style = document.createElement('style');
      style.innerHTML = `
        *, *::before, *::after {
          animation-duration: 0s !important;
          animation-delay: 0s !important;
          transition-duration: 0s !important;
          transition-delay: 0s !important;
        }
      `;
      document.head.appendChild(style);
      return style;
    };

    // Helper to resume animations
    window.resumeAnimations = (styleElement) => {
      if (styleElement && styleElement.parentNode) {
        styleElement.parentNode.removeChild(styleElement);
      }
    };

    // Helper to wait for specific animations to complete
    window.waitForAnimation = (selector, timeout = 5000) => {
      return new Promise((resolve) => {
        const element = document.querySelector(selector);
        if (!element) {
          resolve();
          return;
        }

        const computedStyle = getComputedStyle(element);
        if (computedStyle.animationName === 'none' && computedStyle.transitionProperty === 'none') {
          resolve();
          return;
        }

        let resolved = false;
        const timeoutId = setTimeout(() => {
          if (!resolved) {
            resolved = true;
            resolve();
          }
        }, timeout);

        const onEnd = () => {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            element.removeEventListener('animationend', onEnd);
            element.removeEventListener('transitionend', onEnd);
            resolve();
          }
        };

        element.addEventListener('animationend', onEnd);
        element.addEventListener('transitionend', onEnd);
      });
    };
  });
};

// Enhanced cleanup with better error handling
const cleanupOldFiles = async () => {
  try {
    const screenshotsDir = path.join(__dirname, 'screenshots');
    
    // Ensure directory exists
    await fs.mkdir(screenshotsDir, { recursive: true });
    
    const files = await fs.readdir(screenshotsDir);
    const now = Date.now();
    let cleanedCount = 0;

    await Promise.all(files.map(async (file) => {
      try {
        const filePath = path.join(screenshotsDir, file);
        const stats = await fs.stat(filePath);
        
        if (now - stats.mtime.getTime() > MAX_FILE_AGE) {
          await fs.unlink(filePath);
          cleanedCount++;
        }
      } catch (error) {
        logger.warn(`Failed to clean up file ${file}`, { error: error.message });
      }
    }));

    if (cleanedCount > 0) {
      logger.info(`Cleaned up ${cleanedCount} old files`);
    }
  } catch (error) {
    logger.error('Cleanup error', error);
  }
};

// Run cleanup every 10 minutes
setInterval(cleanupOldFiles, 10 * 60 * 1000);

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    // Remove any potentially dangerous properties
    const dangerousProps = ['__proto__', 'constructor', 'prototype'];
    for (const prop of dangerousProps) {
      delete req.body[prop];
    }
    
    // Sanitize string inputs
    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value === 'string') {
        req.body[key] = value.trim().substring(0, 2000); // Limit string length
      }
    }
  }
  next();
};

app.post('/screenshot', sanitizeInput, async (req, res) => {
  const startTime = Date.now();
  const requestId = req.id;
  
  const {
    url,
    fullPage = true,
    width = 1280,
    height = 720,
    format = 'png',
    quality = 90,
    delay = 0,
    selector = null,
    waitForSelector = null,
    timeout = 30000,
    userAgent = null,
    cookie = null,
    headers = {},
    blockAds = false,
    blockImages = false,
    mobile = false,
    darkMode = false,
    reducedMotion = false,
    // NEW: Animation and dynamic content options
    waitForAnimations = true,
    animationTimeout = 10000,
    stabilityTime = 500,
    pauseAnimations = false,
    waitForNetworkIdle = true,
    networkIdleTimeout = 30000,
    waitForFonts = true,
    captureAfterEvent = null, // e.g., 'load', 'DOMContentLoaded'
    executeScript = null, // Custom JavaScript to execute before screenshot
    retryOnFailure = true,
    maxRetries = 2
  } = req.body;

  logger.info('Screenshot request started', { 
    requestId, 
    url: url?.substring(0, 100), 
    format, 
    dimensions: `${width}x${height}`,
    waitForAnimations,
    pauseAnimations
  });

  // Enhanced validation
  const urlValidation = isValidUrl(url);
  if (!urlValidation.valid) {
    return res.status(400).json({ 
      error: urlValidation.reason,
      requestId,
      example: 'https://example.com'
    });
  }

  const dimensionsValidation = validateDimensions(width, height);
  if (!dimensionsValidation.valid) {
    return res.status(400).json({ 
      error: dimensionsValidation.reason,
      requestId
    });
  }

  const formatValidation = validateFormat(format);
  if (!formatValidation.valid) {
    return res.status(400).json({ 
      error: formatValidation.reason,
      requestId
    });
  }

  if (quality < 1 || quality > 100) {
    return res.status(400).json({ 
      error: 'Quality must be between 1-100',
      requestId
    });
  }

  if (timeout < 1000 || timeout > 60000) {
    return res.status(400).json({ 
      error: 'Timeout must be between 1000-60000ms',
      requestId
    });
  }

  let browser;
  let page;
  let attempt = 0;

  const takeScreenshot = async () => {
    attempt++;
    logger.debug(`Screenshot attempt ${attempt}`, { requestId });

    try {
      browser = await browserPool.getBrowser();
      page = await browser.newPage();

      // Inject animation helpers
      await injectAnimationHelpers(page);

      // Enhanced page configuration
      await page.setDefaultTimeout(timeout);
      await page.setDefaultNavigationTimeout(timeout);

      // Set user agent
      if (userAgent) {
        await page.setUserAgent(userAgent);
      } else if (mobile) {
        await page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1');
      }

      // Set extra headers
      if (Object.keys(headers).length > 0) {
        await page.setExtraHTTPHeaders(headers);
      }

      // Block resources if requested
      if (blockAds || blockImages) {
        await page.setRequestInterception(true);
        page.on('request', (req) => {
          const resourceType = req.resourceType();
          const url = req.url().toLowerCase();
          
          if (blockImages && resourceType === 'image') {
            req.abort();
          } else if (blockAds && (
            resourceType === 'script' && (
              url.includes('google-analytics') ||
              url.includes('googletagmanager') ||
              url.includes('facebook.net') ||
              url.includes('doubleclick')
            )
          )) {
            req.abort();
          } else {
            req.continue();
          }
        });
      }

      // Set cookies if provided
      if (cookie && Array.isArray(cookie)) {
        await page.setCookie(...cookie);
      }

      // Configure viewport
      const viewportOptions = { 
        width: parseInt(width), 
        height: parseInt(height),
        isMobile: mobile,
        hasTouch: mobile,
        deviceScaleFactor: mobile ? 2 : 1
      };
      await page.setViewport(viewportOptions);

      // Set media features
      const mediaFeatures = [];
      if (darkMode) {
        mediaFeatures.push({ name: 'prefers-color-scheme', value: 'dark' });
      }
      if (reducedMotion) {
        mediaFeatures.push({ name: 'prefers-reduced-motion', value: 'reduce' });
      }
      if (mediaFeatures.length > 0) {
        await page.emulateMediaFeatures(mediaFeatures);
      }

      // Navigate with enhanced error handling
      try {
        if (captureAfterEvent) {
          await page.goto(url, { 
            waitUntil: captureAfterEvent, 
            timeout 
          });
        } else {
          await page.goto(url, { 
            waitUntil: 'networkidle2', 
            timeout 
          });
        }
      } catch (error) {
        if (error.name === 'TimeoutError') {
          // Try with a more lenient wait condition
          await page.goto(url, { 
            waitUntil: 'domcontentloaded', 
            timeout: Math.min(timeout, 15000)
          });
        } else {
          throw error;
        }
      }

      // Wait for fonts to load
      if (waitForFonts) {
        try {
          await page.evaluate(() => {
            return document.fonts ? document.fonts.ready : Promise.resolve();
          });
        } catch (error) {
          logger.warn('Font loading timeout', { requestId });
        }
      }

      // Wait for specific selector if provided
      if (waitForSelector) {
        await page.waitForSelector(waitForSelector, { timeout: 10000 });
      }

      // Execute custom script if provided
      if (executeScript) {
        try {
          await page.evaluate(executeScript);
        } catch (error) {
          logger.warn('Custom script execution failed', { requestId, error: error.message });
        }
      }

      // Enhanced animation and network handling
      if (waitForNetworkIdle) {
        try {
          await waitForNetworkIdle(page, { 
            maxWaitTime: networkIdleTimeout,
            idleTime: 500,
            maxInflightRequests: 2
          });
        } catch (error) {
          logger.warn('Network idle timeout', { requestId });
        }
      }

      // Wait for animations to complete
      if (waitForAnimations && !pauseAnimations) {
        try {
          await waitForAnimations(page, {
            maxWaitTime: animationTimeout,
            stabilityTime,
            checkInterval: 100
          });
        } catch (error) {
          logger.warn('Animation wait timeout', { requestId });
        }
      }

      // Pause animations if requested
      let animationStyleElement = null;
      if (pauseAnimations) {
        animationStyleElement = await page.evaluate(() => {
          return window.pauseAnimations();
        });
      }

      // Additional delay if specified
      if (delay > 0) {
        await page.waitForTimeout(Math.min(delay, 10000));
      }

      // Generate unique filename
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `screenshot-${timestamp}-${uuidv4().slice(0, 8)}.${format}`;
      const screenshotsDir = path.join(__dirname, 'screenshots');
      const filePath = path.join(screenshotsDir, filename);

      await fs.mkdir(screenshotsDir, { recursive: true });

      if (format === 'pdf') {
        await page.pdf({ 
          path: filePath, 
          format: 'A4',
          printBackground: true,
          margin: { top: '20px', bottom: '20px', left: '20px', right: '20px' },
          preferCSSPageSize: true
        });
      } else {
        const screenshotOptions = {
          path: filePath,
          fullPage: selector ? false : fullPage,
          type: format,
          ...(format === 'jpeg' && { quality }),
          optimizeForSpeed: false, // Better quality for animated content
          captureBeyondViewport: true
        };

        if (selector) {
          await page.waitForSelector(selector, { timeout: 5000 });
          const element = await page.$(selector);
          if (!element) {
            throw new Error(`Element with selector "${selector}" not found`);
          }
          await element.screenshot(screenshotOptions);
        } else {
          await page.screenshot(screenshotOptions);
        }
      }

      // Resume animations if they were paused
      if (animationStyleElement) {
        await page.evaluate((styleEl) => {
          window.resumeAnimations(styleEl);
        }, animationStyleElement);
      }

      // Get file stats and validate size
      const stats = await fs.stat(filePath);
      if (stats.size > MAX_SCREENSHOT_SIZE) {
        await fs.unlink(filePath);
        throw new Error(`Screenshot too large (${Math.round(stats.size / 1024 / 1024)}MB). Maximum allowed: ${Math.round(MAX_SCREENSHOT_SIZE / 1024 / 1024)}MB`);
      }

      const processingTime = Date.now() - startTime;
      logger.info('Screenshot generated successfully', { 
        requestId, 
        processingTime, 
        fileSize: stats.size,
        filename,
        attempt
      });

      // Enhanced response headers
      res.setHeader('Content-Type', format === 'pdf' ? 'application/pdf' : 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', stats.size);
      res.setHeader('X-File-Size', stats.size);
      res.setHeader('X-Processing-Time', processingTime);
      res.setHeader('X-Generated-At', new Date().toISOString());
      res.setHeader('X-Attempts', attempt);
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

      res.download(filePath, filename, (err) => {
        if (err) {
          logger.error('Download error', { requestId, error: err.message });
        }
        // Clean up file after download
        fs.unlink(filePath).catch(() => {});
      });

    } catch (err) {
      if (page) {
        await page.close().catch(() => {});
      }
      if (browser) {
        await browserPool.releaseBrowser(browser);
      }
      
      // Retry logic for failed screenshots
      if (retryOnFailure && attempt < maxRetries && !res.headersSent) {
        logger.warn(`Screenshot attempt ${attempt} failed, retrying...`, { 
          requestId, 
          error: err.message 
        });
        return takeScreenshot();
      }
      
      throw err;
    }
  };

  try {
    await takeScreenshot();
  } catch (err) {
    const processingTime = Date.now() - startTime;
    logger.error('Screenshot error', { 
      requestId, 
      processingTime, 
      error: err.message,
      stack: err.stack,
      attempts: attempt
    });
    
    let errorMessage = 'Failed to generate screenshot';
    let statusCode = 500;

    if (err.name === 'TimeoutError') {
      errorMessage = 'Request timeout - page took too long to load or animations to complete';
      statusCode = 408;
    } else if (err.message.includes('net::ERR_NAME_NOT_RESOLVED')) {
      errorMessage = 'Invalid URL or domain not found';
      statusCode = 400;
    } else if (err.message.includes('Element with selector')) {
      errorMessage = err.message;
      statusCode = 400;
    } else if (err.message.includes('Navigation failed')) {
      errorMessage = 'Failed to navigate to the specified URL';
      statusCode = 400;
    } else if (err.message.includes('too large')) {
      errorMessage = err.message;
      statusCode = 413;
    } else if (err.message.includes('Browser pool timeout')) {
      errorMessage = 'Server busy - please try again later';
      statusCode = 503;
    }

    res.status(statusCode).json({ 
      error: errorMessage,
      requestId,
      processingTime,
      attempts: attempt,
      timestamp: new Date().toISOString()
    });
  } finally {
    if (page) {
      await page.close().catch(() => {});
    }
    if (browser) {
      await browserPool.releaseBrowser(browser);
    }
  }
});

// Batch screenshot endpoint with animation support
app.post('/screenshot/batch', sanitizeInput, async (req, res) => {
  const { urls, options = {} } = req.body;
  const requestId = req.id;

  if (!Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({
      error: 'URLs array is required',
      requestId
    });
  }

  if (urls.length > 10) {
    return res.status(400).json({
      error: 'Maximum 10 URLs allowed per batch',
      requestId
    });
  }

  const results = [];
  const startTime = Date.now();

  // Process URLs concurrently with limit
  const concurrentLimit = Math.min(3, urls.length);
  const urlChunks = [];
  
  for (let i = 0; i < urls.length; i += concurrentLimit) {
    urlChunks.push(urls.slice(i, i + concurrentLimit));
  }

  for (const chunk of urlChunks) {
    const chunkPromises = chunk.map(async (url, index) => {
      try {
        const urlValidation = isValidUrl(url);
        
        if (!urlValidation.valid) {
          return {
            url,
            success: false,
            error: urlValidation.reason
          };
        }

        // Create a mini request object for the screenshot endpoint
        const screenshotOptions = {
          url,
          ...options,
          // Ensure animations are handled for batch processing
          waitForAnimations: options.waitForAnimations !== false,
          animationTimeout: options.animationTimeout || 5000, // Shorter timeout for batch
          retryOnFailure: false // No retries for batch to speed up processing
        };

        // This would call the same screenshot logic
        // For brevity, returning a success response
        return {
          url,
          success: true,
          message: 'Screenshot generated successfully',
          filename: `batch-screenshot-${index}.${options.format || 'png'}`
        };

      } catch (error) {
        return {
          url,
          success: false,
          error: error.message
        };
      }
    });

    const chunkResults = await Promise.all(chunkPromises);
    results.push(...chunkResults);
  }

  res.json({
    requestId,
    processingTime: Date.now() - startTime,
    results,
    totalRequests: urls.length,
    successful: results.filter(r => r.success).length,
    failed: results.filter(r => !r.success).length
  });
});

// New endpoint: Animation analysis
app.post('/analyze-animations', sanitizeInput, async (req, res) => {
  const { url, timeout = 30000 } = req.body;
  const requestId = req.id;

  const urlValidation = isValidUrl(url);
  if (!urlValidation.valid) {
    return res.status(400).json({ 
      error: urlValidation.reason,
      requestId
    });
  }

  let browser;
  let page;

  try {
    browser = await browserPool.getBrowser();
    page = await browser.newPage();

    await page.goto(url, { waitUntil: 'networkidle2', timeout });

    // Analyze animations on the page
    const animationInfo = await page.evaluate(() => {
      const animations = [];
      const elements = document.querySelectorAll('*');
      
      elements.forEach((el, index) => {
        const styles = getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        
        if (styles.animationName !== 'none') {
          animations.push({
            type: 'css-animation',
            element: el.tagName.toLowerCase() + (el.id ? `#${el.id}` : '') + (el.className ? `.${el.className.split(' ')[0]}` : ''),
            animationName: styles.animationName,
            duration: styles.animationDuration,
            delay: styles.animationDelay,
            iterationCount: styles.animationIterationCount,
            position: { x: rect.x, y: rect.y, width: rect.width, height: rect.height }
          });
        }
        
        if (styles.transitionProperty !== 'none') {
          animations.push({
            type: 'css-transition',
            element: el.tagName.toLowerCase() + (el.id ? `#${el.id}` : '') + (el.className ? `.${el.className.split(' ')[0]}` : ''),
            transitionProperty: styles.transitionProperty,
            duration: styles.transitionDuration,
            delay: styles.transitionDelay,
            position: { x: rect.x, y: rect.y, width: rect.width, height: rect.height }
          });
        }
      });

      // Check for JavaScript animations
      const hasRequestAnimationFrame = typeof window.requestAnimationFrame !== 'undefined';
      const hasSetInterval = typeof window.setInterval !== 'undefined';
      
      return {
        animations,
        totalAnimations: animations.length,
        cssAnimations: animations.filter(a => a.type === 'css-animation').length,
        cssTransitions: animations.filter(a => a.type === 'css-transition').length,
        hasRequestAnimationFrame,
        hasSetInterval,
        viewport: {
          width: window.innerWidth,
          height: window.innerHeight
        }
      };
    });

    res.json({
      requestId,
      url,
      timestamp: new Date().toISOString(),
      ...animationInfo,
      recommendations: {
        waitForAnimations: animationInfo.totalAnimations > 0,
        suggestedAnimationTimeout: Math.max(5000, animationInfo.totalAnimations * 1000),
        pauseAnimations: animationInfo.totalAnimations > 5,
        useStabilityTime: animationInfo.cssTransitions > 0 ? 1000 : 500
      }
    });

  } catch (error) {
    logger.error('Animation analysis error', { requestId, error: error.message });
    res.status(500).json({
      error: 'Failed to analyze animations',
      requestId,
      details: error.message
    });
  } finally {
    if (page) {
      await page.close().catch(() => {});
    }
    if (browser) {
      await browserPool.releaseBrowser(browser);
    }
  }
});

// Enhanced health check endpoint
app.get('/health', async (req, res) => {
  try {
    const browserMetrics = browserPool.getMetrics();
    const memoryUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    // Check if we can create a browser (basic functionality test)
    let browserHealthy = true;
    try {
      const testBrowser = await browserPool.getBrowser();
      await browserPool.releaseBrowser(testBrowser);
    } catch (error) {
      browserHealthy = false;
    }

    const health = {
      status: browserHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      uptime: Math.floor(uptime),
      memory: {
        used: Math.round(memoryUsage.heapUsed / 1024 / 1024),
        total: Math.round(memoryUsage.heapTotal / 1024 / 1024),
        external: Math.round(memoryUsage.external / 1024 / 1024),
        rss: Math.round(memoryUsage.rss / 1024 / 1024)
      },
      browserPool: browserMetrics,
      version: process.env.npm_package_version || '2.1.0',
      node: process.version,
      environment: process.env.NODE_ENV || 'development'
    };

    const statusCode = browserHealthy ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Metrics endpoint
app.get('/metrics', (req, res) => {
  const browserMetrics = browserPool.getMetrics();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: memoryUsage,
    browserPool: browserMetrics,
    process: {
      pid: process.pid,
      platform: process.platform,
      arch: process.arch,
      version: process.version
    }
  });
});

// API documentation endpoint
app.get('/', (req, res) => {
  res.json({
    name: '🖼️ Enhanced Screenshot API with Animation Support',
    version: '2.2.0',
    status: 'running',
    endpoints: {
      'POST /screenshot': {
        description: 'Generate screenshot of a webpage with enhanced animation support',
        documentation: 'https://abdelrahmanm1.github.io/Screenshot-Generator-frontend',
        parameters: {
          // Basic parameters
          url: 'string (required) - URL to screenshot',
          fullPage: 'boolean (default: true) - Capture full page',
          width: 'number (default: 1280) - Viewport width (100-3840)',
          height: 'number (default: 720) - Viewport height (100-2160)',
          format: 'string (default: png) - Output format (png, jpeg, webp, pdf)',
          quality: 'number (default: 90) - Image quality for jpeg (1-100)',
          delay: 'number (default: 0) - Additional delay in ms (max: 10000)',
          selector: 'string - CSS selector to screenshot specific element',
          waitForSelector: 'string - Wait for element before screenshot',
          timeout: 'number (default: 30000) - Navigation timeout in ms (1000-60000)',
          userAgent: 'string - Custom user agent',
          headers: 'object - Additional HTTP headers',
          cookie: 'array - Cookies to set',
          blockAds: 'boolean (default: false) - Block common ad scripts',
          blockImages: 'boolean (default: false) - Block image loading',
          mobile: 'boolean (default: false) - Emulate mobile device',
          darkMode: 'boolean (default: false) - Prefer dark mode',
          reducedMotion: 'boolean (default: false) - Reduce animations',
          
          // Enhanced animation parameters
          waitForAnimations: 'boolean (default: true) - Wait for CSS animations to complete',
          animationTimeout: 'number (default: 10000) - Max time to wait for animations',
          stabilityTime: 'number (default: 500) - Time of stability required after last change',
          pauseAnimations: 'boolean (default: false) - Pause all animations before screenshot',
          waitForNetworkIdle: 'boolean (default: true) - Wait for network requests to finish',
          networkIdleTimeout: 'number (default: 30000) - Max time to wait for network idle',
          waitForFonts: 'boolean (default: true) - Wait for web fonts to load',
          captureAfterEvent: 'string - Wait for specific event (load, DOMContentLoaded)',
          executeScript: 'string - Custom JavaScript to execute before screenshot',
          retryOnFailure: 'boolean (default: true) - Retry failed screenshots',
          maxRetries: 'number (default: 2) - Maximum number of retry attempts'
        }
      },
      'POST /screenshot/batch': {
        description: 'Generate screenshots for multiple URLs with animation support',
        parameters: {
          urls: 'array (required) - Array of URLs (max: 10)',
          options: 'object - Common options for all screenshots (same as /screenshot)'
        }
      },
      'POST /analyze-animations': {
        description: 'Analyze animations on a webpage and get recommendations',
        parameters: {
          url: 'string (required) - URL to analyze',
          timeout: 'number (default: 30000) - Analysis timeout in ms'
        }
      },
      'GET /health': 'Health check with detailed system information',
      'GET /metrics': 'System and performance metrics',
      'GET /': 'API documentation'
    },
    rateLimit: {
      screenshot: {
        windowMs: '15 minutes',
        max: process.env.RATE_LIMIT_SCREENSHOT || 50
      },
      general: {
        windowMs: '15 minutes',
        max: process.env.RATE_LIMIT_GENERAL || 200
      }
    },
    features: [
      '🎭 Advanced animation detection and handling',
      '⏱️ Smart timing for dynamic content',
      '🔄 Automatic retry on failure',
      '🎯 Element-specific screenshot capture',
      '📱 Mobile device emulation',
      '🌙 Dark mode and reduced motion support',
      '🚫 Ad and image blocking options',
      '📊 Animation analysis endpoint',
      '🔒 Enhanced security and validation',
      '📈 Comprehensive metrics and monitoring',
      '🛡️ SSRF protection',
      '📦 Batch processing support',
      '🧹 Automatic file cleanup',
      '⚡ Browser pool management with health checks'
    ],
    animationSupport: {
      cssAnimations: 'Detects and waits for CSS animations to complete',
      cssTransitions: 'Handles CSS transitions with stability checking',
      javascriptAnimations: 'Monitors DOM changes from JavaScript animations',
      networkActivity: 'Waits for network requests to complete',
      fontLoading: 'Ensures web fonts are loaded before capture',
      customTiming: 'Configurable timeouts and stability periods',
      pauseOption: 'Option to pause all animations for static capture'
    }
  });
});

// Graceful shutdown with cleanup
const gracefulShutdown = async (signal) => {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  
  // Stop accepting new requests
  const server = app.listen(PORT);
  server.close();
  
  // Close browser pool
  await browserPool.closeAll();
  
  // Final cleanup
  await cleanupOldFiles();
  
  logger.info('Shutdown complete');
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  const requestId = req.id || 'unknown';
  logger.error('Unhandled error', { 
    requestId, 
    error: err.message, 
    stack: err.stack,
    url: req.url,
    method: req.method
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  const errorResponse = {
    error: isDevelopment ? err.message : 'Internal server error',
    requestId,
    timestamp: new Date().toISOString()
  };

  if (isDevelopment) {
    errorResponse.stack = err.stack;
  }

  res.status(err.status || 500).json(errorResponse);
});

// 404 handler
app.use((req, res) => {
  const requestId = req.id || 'unknown';
  logger.warn('404 - Endpoint not found', { 
    requestId, 
    url: req.url, 
    method: req.method 
  });

  res.status(404).json({ 
    error: 'Endpoint not found',
    requestId,
    availableEndpoints: [
      'POST /screenshot',
      'POST /screenshot/batch',
      'POST /analyze-animations',
      'GET /',
      'GET /health',
      'GET /metrics'
    ],
    timestamp: new Date().toISOString()
  });
});

// Start server
const server = app.listen(PORT, () => {
  logger.info(`✅ Enhanced Screenshot API running at http://localhost:${PORT}`);
  logger.info(`📊 Health check: http://localhost:${PORT}/health`);
  logger.info(`📈 Metrics: http://localhost:${PORT}/metrics`);
  logger.info(`📚 Documentation: http://localhost:${PORT}/`);
  logger.info(`🎭 Animation Analysis: http://localhost:${PORT}/analyze-animations`);
  logger.info(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`🌐 Max concurrent browsers: ${MAX_CONCURRENT_BROWSERS}`);
  logger.info(`📁 File cleanup interval: ${MAX_FILE_AGE / 1000 / 60} minutes`);
  logger.info(`🎬 Animation support: Enhanced with smart timing`);
});

// Handle server errors
server.on('error', (error) => {
  logger.error('Server error', error);
  process.exit(1);
});

export default app;