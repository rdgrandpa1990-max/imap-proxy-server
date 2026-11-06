import express from 'express';
import crypto from 'crypto';
import admin from 'firebase-admin';
import { verifyFirebaseAuth, requireRoles } from './authMiddleware.js';

const router = express.Router();
function getDbInstance() {
  if (!admin.apps.length) {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      try {
        const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        admin.initializeApp({ credential: admin.credential.cert(sa) });
      } catch {
        admin.initializeApp({ projectId: 'ff-store-4a61e' });
      }
    } else {
      admin.initializeApp({ projectId: 'ff-store-4a61e' });
    }
  }
  return admin.firestore();
}

const db = new Proxy({}, {
  get(target, prop) {
    const firestoreInstance = getDbInstance();
    const val = firestoreInstance[prop];
    return typeof val === 'function' ? val.bind(firestoreInstance) : val;
  }
});

// Timing-safe constant-time string comparison for webhook/API secrets
function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length === 0 || bufB.length === 0 || bufA.length !== bufB.length) {
    const dummy = Buffer.alloc(32, 0);
    crypto.timingSafeEqual(dummy, dummy);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Strict URL validation: must be valid HTTPS
function isValidReleaseUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return false;
  try {
    const parsed = new URL(urlStr);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

// Strict SHA-256 hash validation: exactly 64 hexadecimal characters
function isValidSha256(hashStr) {
  if (!hashStr || typeof hashStr !== 'string') return false;
  return /^[a-fA-F0-9]{64}$/.test(hashStr.trim());
}

// =========================================================================
// 1. Mandatory App Version & APK Check (Phase 8 - CFG-03)
// =========================================================================
router.get('/api/v1/app/version-check', async (req, res) => {
  try {
    const clientPlatform = String(req.query.platform || 'android').toLowerCase().trim();
    const clientVersionCode = parseInt(req.query.versionCode, 10) || 0;

    // Default configuration (configurable via environment or Firestore /app_config/android)
    let minVersionCode = parseInt(process.env.MINIMUM_ANDROID_VERSION_CODE, 10) || 1;
    let latestVersionCode = parseInt(process.env.LATEST_ANDROID_VERSION_CODE, 10) || 2;
    let latestVersionName = process.env.LATEST_ANDROID_VERSION_NAME || '1.0.1';
    let downloadUrl = process.env.LATEST_APK_DOWNLOAD_URL || 'https://github.com/rdgrandpa1990-max/gamervoult-app/releases/download/v1.0.1/gamervoult-v1.0.1.apk';
    let sha256Checksum = process.env.LATEST_APK_SHA256 || null;
    let fileSizeBytes = process.env.LATEST_APK_SIZE_BYTES ? parseInt(process.env.LATEST_APK_SIZE_BYTES, 10) : null;
    let changelog = process.env.APP_CHANGELOG || '• In-app OTA APK auto-updater with live progress\n• 3D GamerVault Experience & Escrow Desk\n• Real-time Support Chat with Our Team';

    // Check Firestore /app_config/android for live override
    if (db) {
      try {
        const configSnap = await db.collection('app_config').doc(clientPlatform).get();
        if (configSnap.exists) {
          const cfg = configSnap.data();
          if (cfg.minVersionCode != null) minVersionCode = parseInt(cfg.minVersionCode, 10);
          if (cfg.latestVersionCode != null) latestVersionCode = parseInt(cfg.latestVersionCode, 10);
          if (cfg.latestVersionName) latestVersionName = String(cfg.latestVersionName);
          if (cfg.downloadUrl) downloadUrl = String(cfg.downloadUrl);
          if (cfg.sha256Checksum) sha256Checksum = String(cfg.sha256Checksum);
          if (cfg.fileSizeBytes != null) fileSizeBytes = parseInt(cfg.fileSizeBytes, 10);
          if (cfg.changelog) changelog = String(cfg.changelog);
        }
      } catch (dbErr) {
        console.warn('[VersionCheck] Firestore config fallback warning:', dbErr.message);
      }
    }

    const mandatoryUpdate = clientVersionCode < minVersionCode;
    const updateAvailable = clientVersionCode < latestVersionCode;
    const isArtifactAvailable = Boolean(downloadUrl && isValidReleaseUrl(downloadUrl));

    return res.status(200).json({
      success: true,
      platform: clientPlatform,
      clientVersionCode,
      minVersionCode,
      latestVersionCode,
      latestVersionName,
      updateAvailable,
      mandatoryUpdate,
      isArtifactAvailable,
      downloadUrl: downloadUrl || 'https://github.com/rdgrandpa1990-max/gamervoult-app/releases/download/v1.0.1/gamervoult-v1.0.1.apk',
      sha256Checksum: sha256Checksum || null,
      fileSizeBytes: fileSizeBytes || null,
      changelog,
      checkedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[VersionCheck] Internal error:', err);
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Failed to verify application version.'
    });
  }
});

// =========================================================================
// 2. Gamervoult Stories & Announcements (Phase 8)
// =========================================================================

// GET /api/v1/stories/active — List active, non-expired stories
router.get('/api/v1/stories/active', async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  try {
    const now = Date.now();
    const snapshot = await db.collection('stories')
      .where('expiresAt', '>', now)
      .orderBy('expiresAt', 'asc')
      .limit(50)
      .get();

    const stories = [];
    snapshot.forEach(docSnap => {
      stories.push({ id: docSnap.id, ...docSnap.data() });
    });

    return res.status(200).json({
      success: true,
      count: stories.length,
      stories
    });
  } catch (err) {
    console.error('[Stories] Fetch error:', err.message);
    // If composite index is pending, fallback to in-memory filter
    try {
      const snap = await db.collection('stories').limit(50).get();
      const now = Date.now();
      const fallbackList = [];
      snap.forEach(d => {
        const data = d.data();
        if (!data.expiresAt || data.expiresAt > now) {
          fallbackList.push({ id: d.id, ...data });
        }
      });
      return res.status(200).json({ success: true, count: fallbackList.length, stories: fallbackList });
    } catch (fallbackErr) {
      return res.status(500).json({ success: false, error: 'Failed to fetch stories.' });
    }
  }
});

// POST /api/v1/stories/publish — Admin / SuperAdmin strictly
router.post('/api/v1/stories/publish', verifyFirebaseAuth, requireRoles(['admin', 'superadmin']), async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  const { mediaUrl, mediaType = 'image', caption = '', durationHours = 24 } = req.body;

  if (!mediaUrl || typeof mediaUrl !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing required field: mediaUrl' });
  }

  const duration = Math.min(Math.max(parseInt(durationHours, 10) || 24, 1), 168); // 1h to 7 days
  const now = Date.now();
  const expiresAt = now + duration * 3600 * 1000;

  try {
    const storyDoc = {
      mediaUrl: String(mediaUrl).trim(),
      mediaType: mediaType === 'video' ? 'video' : 'image',
      caption: String(caption || '').trim().substring(0, 500),
      authorUid: req.uid,
      authorEmail: req.user.email || 'Admin',
      authorRole: req.userRole,
      createdAt: now,
      expiresAt: expiresAt,
      viewsCount: 0
    };

    const docRef = await db.collection('stories').add(storyDoc);

    return res.status(201).json({
      success: true,
      storyId: docRef.id,
      expiresAt,
      message: `Story published successfully. Valid for ${duration} hours.`
    });
  } catch (err) {
    console.error('[Stories] Publish error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to publish story.' });
  }
});

// DELETE /api/v1/stories/:storyId — Admin / SuperAdmin strictly
router.delete('/api/v1/stories/:storyId', verifyFirebaseAuth, requireRoles(['admin', 'superadmin']), async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  try {
    await db.collection('stories').doc(req.params.storyId).delete();
    return res.status(200).json({ success: true, message: 'Story deleted successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to delete story.' });
  }
});

// =========================================================================
// 3. User Identity & FCM Notification Tokens (Phase 8)
// =========================================================================

// GET /api/v1/me — Current authenticated user profile & entitlements
router.get('/api/v1/me', verifyFirebaseAuth, async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  try {
    const userDoc = req.userData || {};
    let subscriptionData = null;

    const subSnap = await db.collection('subscriptions').doc(req.uid).get();
    if (subSnap.exists) {
      subscriptionData = subSnap.data();
    }

    return res.status(200).json({
      success: true,
      uid: req.uid,
      email: req.user.email,
      role: req.userRole,
      isAdmin: req.isAdmin,
      isStaff: req.isStaff,
      profile: {
        name: userDoc.name || 'Client',
        email: userDoc.email || req.user.email,
        phone: userDoc.phone || userDoc.mobile || null,
        instagram: userDoc.instagram || null,
        status: userDoc.status || 'active',
        createdAt: userDoc.createdAt || null
      },
      subscription: subscriptionData,
      assignedMailbox: userDoc.linkedGmail || userDoc.linkedZoho || userDoc.linkedImap || null
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve profile.' });
  }
});

// POST /api/v1/notifications/register-token — Register FCM token
router.post('/api/v1/notifications/register-token', verifyFirebaseAuth, async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  const { fcmToken, deviceModel = 'Android', osVersion = '' } = req.body;
  if (!fcmToken || typeof fcmToken !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing required field: fcmToken' });
  }

  try {
    const tokenClean = fcmToken.trim();
    const tokenDocId = crypto.createHash('sha256').update(tokenClean).digest('hex').substring(0, 32);

    await db.collection('users').doc(req.uid).collection('fcm_tokens').doc(tokenDocId).set({
      token: tokenClean,
      deviceModel: String(deviceModel).substring(0, 100),
      osVersion: String(osVersion).substring(0, 50),
      updatedAt: new Date().toISOString()
    }, { merge: true });

    return res.status(200).json({ success: true, message: 'FCM device token registered successfully.' });
  } catch (err) {
    console.error('[Notifications] Token registration error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to register notification token.' });
  }
});

// =========================================================================
// 4. Cloudinary Signed Uploads (Phase 6 - Secure Media Uploads)
// =========================================================================
router.post('/api/v1/uploads/sign', verifyFirebaseAuth, async (req, res) => {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME || process.env.VITE_CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY || process.env.VITE_CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET || process.env.VITE_CLOUDINARY_API_SECRET;

  if (!cloudName || !apiKey || !apiSecret) {
    return res.status(503).json({
      success: false,
      error: 'CONFIGURATION_ERROR',
      message: 'Cloudinary server credentials not configured in environment.'
    });
  }

  const { folder = 'gamervoult/media', resourceType = 'image' } = req.body;
  const timestamp = Math.round(Date.now() / 1000);

  // Sign parameters using Cloudinary SHA-1 / SHA-256 HMAC specification
  // Sorted parameter string: `folder=${folder}&timestamp=${timestamp}${apiSecret}`
  const paramsToSign = `folder=${folder}&timestamp=${timestamp}${apiSecret}`;
  const signature = crypto.createHash('sha1').update(paramsToSign).digest('hex');

  return res.status(200).json({
    success: true,
    cloudName,
    apiKey,
    timestamp,
    signature,
    folder,
    resourceType: resourceType === 'video' ? 'video' : 'image'
  });
});

// =========================================================================
// 5. Payment Orders: Server-Controlled Workflow (Phase 5)
// =========================================================================

// POST /api/v1/orders/create — Server creates payment order via gateway
router.post('/api/v1/orders/create', async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  const { itemId, customerName, customerPhone, customNote } = req.body;

  if (!itemId || !customerName || !customerPhone) {
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Required fields: itemId, customerName, customerPhone'
    });
  }

  try {
    // 1. Verify item existence and actual price from database (prevents client price tampering)
    const itemSnap = await db.collection('ff_store').doc(String(itemId)).get();
    if (!itemSnap.exists) {
      return res.status(404).json({ success: false, error: 'Store item not found.' });
    }

    const itemData = itemSnap.data();
    let price = Number(itemData.price);
    if (isNaN(price) || price < 0) {
      price = 0;
    }

    // 2. Coupon & Discount handling
    const { couponCode, discountAmount } = req.body;
    let discount = 0;
    if (discountAmount && !isNaN(discountAmount) && Number(discountAmount) > 0) {
      discount = Number(discountAmount);
      price = Math.max(0, price - discount);
    }

    // 3. Gateway Credentials (Hydrated from Firestore system_settings/payment_gateway if not in env)
    let gatewayUrl = (process.env.UPI_GATEWAY_URL || 'https://personal-payment-gateway.onrender.com').replace(/\/+$/, '');
    let gatewayApiKey = process.env.UPI_GATEWAY_API_KEY || '';

    if (!gatewayApiKey && db) {
      try {
        const gwSnap = await db.collection('system_settings').doc('payment_gateway').get();
        if (gwSnap.exists) {
          const gwData = gwSnap.data();
          if (gwData.apiKey) gatewayApiKey = gwData.apiKey;
          if (gwData.gatewayUrl) gatewayUrl = gwData.gatewayUrl.trim().replace(/\/+$/, '');
        }
      } catch (gwErr) {
        console.warn('[Orders] Gateway credentials fetch warning:', gwErr.message);
      }
    }

    // Generate clean internal order code: ORD-XXXXXX
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let codeRand = '';
    for (let i = 0; i < 6; i++) {
      codeRand += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const orderCode = `ORD-${codeRand}`;

    // 3. Call External Gateway
    let gwOrder = null;
    if (gatewayApiKey) {
      try {
        const gwRes = await fetch(`${gatewayUrl}/api/v1/orders`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': gatewayApiKey
          },
          body: JSON.stringify({
            amount: price,
            customerName: String(customerName).trim(),
            customerPhone: String(customerPhone).trim(),
            customNote: customNote || `Gamervoult Store: ${itemData.title || 'Game Account'}`
          })
        });

        if (gwRes.ok) {
          const gwJson = await gwRes.json();
          gwOrder = gwJson.order || gwJson;
        }
      } catch (gwErr) {
        console.warn('[Orders] Gateway call warning:', gwErr.message);
      }
    }

    const effectiveOrderCode = gwOrder?.orderCode || orderCode;
    const qrImageUrl = gwOrder?.qrImageUrl || `${gatewayUrl}/api/v1/orders/${effectiveOrderCode}/qr.png`;
    const fullCheckoutUrl = gwOrder?.fullCheckoutUrl || `${gatewayUrl}/checkout/${effectiveOrderCode}`;
    const upiUri = gwOrder?.upiUri || `upi://pay?pn=GAMERVAULT%20ESCROW&am=${price}&cu=INR&tn=${effectiveOrderCode}`;

    // 4. Save Order in Firestore (SEC-CRIT-03 Fix: NEVER save plaintext passwords here!)
    const orderRecord = {
      orderCode: effectiveOrderCode,
      amount: price,
      customerName: String(customerName).trim(),
      customerPhone: String(customerPhone).trim(),
      userId: req.uid || null,
      itemId: String(itemId),
      itemTitle: itemData.title || 'Free Fire Account',
      accountUid: itemData.accountUid || 'VERIFIED',
      hasDirectCredentials: Boolean(itemData.hasDirectCredentials),
      deliveryMode: itemData.deliveryMode || 'license_shuffle',
      status: 'PENDING',
      qrImageUrl,
      fullCheckoutUrl,
      upiUri,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await db.collection('payment_orders').doc(effectiveOrderCode).set(orderRecord, { merge: true });

    return res.status(201).json({
      success: true,
      order: {
        orderCode: effectiveOrderCode,
        amount: price,
        status: 'PENDING',
        qrImageUrl,
        fullCheckoutUrl,
        upiUri
      }
    });

  } catch (err) {
    console.error('[Orders] Creation error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to create payment order.' });
  }
});

// GET /api/v1/orders/:orderCode — Authoritative status check
router.get('/api/v1/orders/:orderCode', async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  const orderCode = String(req.params.orderCode).trim();

  try {
    const orderRef = db.collection('payment_orders').doc(orderCode);
    const orderSnap = await orderRef.get();

    if (!orderSnap.exists) {
      return res.status(404).json({ success: false, error: 'Order not found.' });
    }

    const orderData = orderSnap.data();

    // If order is already PAID in database, return immediately
    if (orderData.status === 'PAID') {
      return res.status(200).json({
        success: true,
        orderCode,
        status: 'PAID',
        amount: orderData.amount,
        paidAt: orderData.paidAt || orderData.updatedAt,
        utr: orderData.utr || null
      });
    }

    // Query external gateway to verify if status has updated
    let gatewayUrl = (process.env.UPI_GATEWAY_URL || 'https://personal-payment-gateway.onrender.com').replace(/\/+$/, '');
    let gatewayApiKey = process.env.UPI_GATEWAY_API_KEY || '';

    if (!gatewayApiKey && db) {
      try {
        const gwSnap = await db.collection('system_settings').doc('payment_gateway').get();
        if (gwSnap.exists) {
          const gwData = gwSnap.data();
          if (gwData.apiKey) gatewayApiKey = gwData.apiKey;
          if (gwData.gatewayUrl) gatewayUrl = gwData.gatewayUrl.trim().replace(/\/+$/, '');
        }
      } catch (gwErr) {
        console.warn('[Orders] Status poll gateway credentials fetch warning:', gwErr.message);
      }
    }

    if (gatewayApiKey) {
      try {
        const gwRes = await fetch(`${gatewayUrl}/api/v1/orders/${orderCode}`, {
          headers: { 'x-api-key': gatewayApiKey }
        });

        if (gwRes.ok) {
          const gwData = await gwRes.json();
          const gwStatus = gwData.status || gwData.order?.status;

          if (gwStatus === 'PAID' && orderData.status !== 'PAID') {
            // Update to PAID via Firebase Admin SDK (Authoritative backend verification)
            const paidAt = gwData.paidAt || gwData.order?.paidAt || new Date().toISOString();
            const utr = gwData.utr || gwData.order?.utr || 'VERIFIED';

            await orderRef.update({
              status: 'PAID',
              paidAt,
              utr,
              updatedAt: new Date().toISOString()
            });

            return res.status(200).json({
              success: true,
              orderCode,
              status: 'PAID',
              amount: orderData.amount,
              paidAt,
              utr
            });
          }
        }
      } catch (pollErr) {
        console.warn(`[Orders] Gateway poll error for ${orderCode}:`, pollErr.message);
      }
    }

    return res.status(200).json({
      success: true,
      orderCode,
      status: orderData.status || 'PENDING',
      amount: orderData.amount,
      updatedAt: orderData.updatedAt
    });

  } catch (err) {
    return res.status(500).json({ success: false, error: 'Internal order lookup error.' });
  }
});

// POST /api/webhooks/payment — Server-to-server payment gateway callback
router.post('/api/webhooks/payment', async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  // 1. Fail-Closed Authentication: Expected secret MUST be configured and match incoming header
  // Note: VITE_UPI_GATEWAY_API_KEY is deliberately excluded as client-side keys must not be trusted on backend.
  const expectedSecret = process.env.UPI_GATEWAY_WEBHOOK_SECRET || process.env.UPI_GATEWAY_API_KEY || '';
  
  let incomingSecret = req.headers['x-webhook-secret'] || req.headers['x-api-key'] || '';
  if (!incomingSecret && req.headers['authorization']) {
    const authHeader = String(req.headers['authorization']).trim();
    if (authHeader.startsWith('Bearer ')) {
      incomingSecret = authHeader.slice(7).trim();
    } else {
      incomingSecret = authHeader;
    }
  }

  if (!expectedSecret) {
    console.error('[Webhook] CRITICAL: Payment gateway webhook secret is not configured on server. Rejecting call.');
    return res.status(503).json({ success: false, error: 'Configuration Error: Webhook authentication secret not configured.' });
  }

  if (!incomingSecret || !timingSafeEqualStr(String(incomingSecret).trim(), expectedSecret.trim())) {
    console.warn('[Webhook] Rejected unauthorized webhook call: Invalid or missing secret.');
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing webhook secret.' });
  }

  const { orderCode, status, utr, transactionId, amount, currency } = req.body;

  if (!orderCode || !status) {
    return res.status(400).json({ success: false, error: 'Missing required webhook fields: orderCode, status' });
  }

  const cleanOrderCode = String(orderCode).trim();
  const cleanStatus = String(status).trim().toUpperCase();

  const allowedStatuses = ['PAID', 'FAILED', 'EXPIRED'];
  if (!allowedStatuses.includes(cleanStatus)) {
    return res.status(400).json({ success: false, error: `Invalid order status: ${cleanStatus}. Must be one of ${allowedStatuses.join(', ')}` });
  }

  try {
    const orderRef = db.collection('payment_orders').doc(cleanOrderCode);
    const orderSnap = await orderRef.get();

    if (!orderSnap.exists) {
      return res.status(404).json({ success: false, error: 'Order not found in registry.' });
    }

    const currentOrder = orderSnap.data();

    // Idempotent processing & Terminal state lock: if already marked PAID, prevent any conflicting status changes
    if (currentOrder.status === 'PAID') {
      return res.status(200).json({ success: true, message: 'Order already processed as PAID. Status is terminal and cannot be overridden.' });
    }

    // Terminal state lock: if order is CANCELLED, reject transitions
    if (currentOrder.status === 'CANCELLED') {
      return res.status(409).json({ success: false, error: 'Order is already CANCELLED and cannot be modified.' });
    }

    // 2. Currency Validation: ensure currency matches authoritative order currency
    if (currency !== undefined && currency !== null) {
      const orderCurrency = String(currentOrder.currency || 'INR').trim().toUpperCase();
      const webhookCurrency = String(currency).trim().toUpperCase();
      if (webhookCurrency !== orderCurrency) {
        console.error(`[Webhook] Currency mismatch for ${cleanOrderCode}: expected ${orderCurrency}, received ${webhookCurrency}`);
        return res.status(400).json({ success: false, error: `Currency mismatch detected: expected ${orderCurrency}, received ${webhookCurrency}` });
      }
    }

    // 3. Amount Validation: If amount provided in webhook, ensure it strictly matches order amount
    if (amount !== undefined && amount !== null && !isNaN(Number(amount))) {
      const webhookAmount = Number(amount);
      const expectedAmount = Number(currentOrder.amount);
      if (webhookAmount !== expectedAmount) {
        console.error(`[Webhook] Amount mismatch for ${cleanOrderCode}: expected ${expectedAmount}, received ${webhookAmount}`);
        return res.status(400).json({ success: false, error: 'Amount mismatch detected between webhook and order.' });
      }
    }

    // 4. Payment Evidence & Replay Protection for PAID transitions
    const paymentEvidence = utr ? String(utr).trim() : (transactionId ? String(transactionId).trim() : '');

    if (cleanStatus === 'PAID') {
      if (!paymentEvidence || paymentEvidence.length < 4) {
        return res.status(400).json({
          success: false,
          error: 'Missing or invalid payment evidence (UTR / transactionId) required to mark order as PAID.'
        });
      }

      // Replay Protection: Query whether this transaction reference was already recorded on any other order
      const existingUtrDocs = await db.collection('payment_orders')
        .where('utr', '==', paymentEvidence)
        .limit(2)
        .get();

      const isReplayed = existingUtrDocs.docs.some(doc => doc.id !== cleanOrderCode);
      if (isReplayed) {
        console.error(`[Webhook] REPLAY DETECTED: UTR ${paymentEvidence} was already used on another order.`);
        return res.status(409).json({
          success: false,
          error: 'Replay conflict: Payment transaction reference (UTR) has already been applied to another order.'
        });
      }

      await orderRef.update({
        status: 'PAID',
        paidAt: new Date().toISOString(),
        utr: paymentEvidence,
        webhookReceivedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });

      console.log(`✅ [Webhook] Order ${cleanOrderCode} verified and marked PAID with UTR ${paymentEvidence}`);
      return res.status(200).json({ success: true, message: `Payment confirmed and verified for order ${cleanOrderCode}` });
    } else if (cleanStatus === 'FAILED' || cleanStatus === 'EXPIRED') {
      await orderRef.update({
        status: cleanStatus,
        updatedAt: new Date().toISOString()
      });
      return res.status(200).json({ success: true, message: `Status updated to ${cleanStatus} for ${cleanOrderCode}` });
    }

  } catch (err) {
    console.error('[Webhook] Processing error:', err.message);
    return res.status(500).json({ success: false, error: 'Webhook processing failed.' });
  }
});

// POST /api/v1/orders/:orderCode/credentials — Secure Post-Payment Delivery
router.post('/api/v1/orders/:orderCode/credentials', verifyFirebaseAuth, async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: 'Database unavailable' });

  const orderCode = String(req.params.orderCode).trim();

  try {
    const orderSnap = await db.collection('payment_orders').doc(orderCode).get();
    if (!orderSnap.exists) {
      return res.status(404).json({ success: false, error: 'Order not found.' });
    }

    const order = orderSnap.data();

    // 1. Verify Order is PAID
    if (order.status !== 'PAID') {
      return res.status(402).json({
        success: false,
        error: 'PAYMENT_REQUIRED',
        message: 'Order has not been confirmed as PAID. Credentials cannot be released.'
      });
    }

    // 2. Ownership check: Must be the buyer or an administrator
    const isOwner = req.uid === order.userId || (order.customerEmail && req.user.email === order.customerEmail);
    if (!isOwner && !req.isStaff) {
      return res.status(403).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'You are not authorized to access credentials for this order.'
      });
    }

    // 3. Fetch from private, admin-only ff_store_secrets
    const secretSnap = await db.collection('ff_store_secrets').doc(order.itemId).get();
    if (!secretSnap.exists) {
      return res.status(200).json({
        success: true,
        message: 'Account verified. Credentials will be handed over via Support Desk.',
        credentials: {
          accountUid: order.accountUid,
          deliveryMode: order.deliveryMode || 'escrow_manual',
          notes: 'Your payment is confirmed. Please connect with our Official Desk for handover.'
        }
      });
    }

    const sec = secretSnap.data();

    return res.status(200).json({
      success: true,
      orderCode,
      credentials: {
        accountType: sec.deliveryAccountType || 'Google',
        loginId: sec.deliveryLoginId || '',
        password: sec.deliveryPassword || '',
        backupCodes: sec.deliveryBackupCodes || '',
        notes: sec.deliveryNotes || '',
        tutorialUrl: order.deliveryTutorialUrl || ''
      }
    });

  } catch (err) {
    console.error('[Credentials] Release error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to retrieve delivery credentials.' });
  }
});

// =========================================================================
// 6. Server-Side AI Copilot Endpoint (Phase 7 - Protect Gemini API Key)
// =========================================================================
router.post('/api/v1/ai/suggest-reply', verifyFirebaseAuth, requireRoles(['staff', 'employee', 'admin', 'superadmin']), async (req, res) => {
  const geminiApiKey = process.env.GEMINI_API_KEY || '';
  if (!geminiApiKey) {
    return res.status(503).json({ success: false, error: 'GEMINI_API_KEY not configured on server.' });
  }

  const { clientName, clientEmail, messages = [], sellerDraft = '', stylePrompt = '' } = req.body;

  try {
    const recentHistory = messages.slice(-10).map(m => `${m.senderName || 'User'}: ${m.text || ''}`).join('\n');
    const promptText = `You are a professional AI Copilot for Gamervoult Escrow Support Desk. Customer: ${clientName || 'Customer'} (${clientEmail || 'N/A'}).
Seller draft: "${sellerDraft}". Focus: "${stylePrompt}".
Recent messages:
${recentHistory || 'No previous messages.'}

Generate 3 high-impact reply options in JSON format:
[
  { "tone": "Deal Closer & Reassuring", "badge": "🤝 Deal Closer", "reply": "..." },
  { "tone": "Direct Action & Steps", "badge": "⚡ Quick Action", "reply": "..." },
  { "tone": "Escrow & Security Policy", "badge": "🛡️ Policy", "reply": "..." }
]
Output ONLY the JSON array.`;

    const models = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
    let aiResponseJson = null;

    for (const model of models) {
      try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: promptText }] }],
            generationConfig: { temperature: 0.7, maxOutputTokens: 1000 }
          })
        });

        if (response.ok) {
          const data = await response.json();
          const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          const cleanJson = rawText.replace(/```json/gi, '').replace(/```/g, '').trim();
          aiResponseJson = JSON.parse(cleanJson);
          if (Array.isArray(aiResponseJson) && aiResponseJson.length > 0) {
            break;
          }
        }
      } catch (fetchErr) {
        console.warn(`[AI] Model ${model} retry note:`, fetchErr.message);
      }
    }

    if (!aiResponseJson) {
      return res.status(502).json({ success: false, error: 'AI generation returned no valid reply options.' });
    }

    return res.status(200).json({ success: true, options: aiResponseJson });

  } catch (err) {
    console.error('[AI] Suggestion error:', err.message);
    return res.status(500).json({ success: false, error: 'Internal AI generation error.' });
  }
});

// =========================================================================
// 8. Atomic License Key Redemption & Entitlement (Phase 2.3 & Phase 8)
// SEC-HIGH-02 Remediation: Server-enforced, single-use, atomic transaction
// =========================================================================
router.post('/api/v1/license/redeem', verifyFirebaseAuth, async (req, res) => {
  try {
    const rawKey = req.body?.licenseKey;
    if (!rawKey || typeof rawKey !== 'string') {
      return res.status(400).json({ success: false, error: 'License key is required.' });
    }

    const cleanKey = rawKey.trim();
    const uid = req.user.uid;
    const email = (req.user.email || '').toLowerCase().trim();

    if (!db) {
      return res.status(500).json({ success: false, error: 'Firestore database uninitialized.' });
    }

    const keyRef = db.collection('license_keys').doc(cleanKey);
    const userRef = db.collection('users').doc(uid);
    const subRef = db.collection('subscriptions').doc(uid);

    let assignedMailbox = null;
    let mailboxType = null;

    // Run atomic transaction to prevent double redemption race conditions
    await db.runTransaction(async (transaction) => {
      const keyDoc = await transaction.get(keyRef);
      if (!keyDoc.exists) {
        throw new Error('LICENSE_NOT_FOUND');
      }

      const keyData = keyDoc.data();
      if (keyData.status !== 'active') {
        if (keyData.redeemedBy === uid || keyData.redeemedByEmail === email) {
          // Idempotent retry by the same user: proceed to verify/provision subscription
        } else {
          throw new Error('LICENSE_ALREADY_REDEEMED');
        }
      }

      assignedMailbox = keyData.assignedMailbox || null;
      mailboxType = keyData.mailboxType || null;

      const now = new Date();
      const expiry = new Date(now.getTime() + 48 * 60 * 60 * 1000); // 48-hour entitlement

      // 1. Burn license key
      transaction.update(keyRef, {
        status: 'redeemed',
        redeemedBy: uid,
        redeemedByEmail: email,
        redeemedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // 2. Set authoritative subscription
      transaction.set(subRef, {
        productName: 'License Key Activation',
        purchaseDate: now.toISOString(),
        expiryDate: expiry.toISOString(),
        validityDays: 2,
        amountPaid: 0,
        status: 'Active',
        notes: `Activated via License Key: ${cleanKey}`,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // 3. Update user profile
      const userUpdates = {
        role: 'client',
        status: 'Active',
        usedLicenseKey: cleanKey,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      };
      if (mailboxType === 'gmail' && assignedMailbox) userUpdates.linkedGmail = assignedMailbox;
      if (mailboxType === 'zoho' && assignedMailbox) userUpdates.linkedZoho = assignedMailbox;
      if (mailboxType === 'imap' && assignedMailbox) userUpdates.linkedImap = assignedMailbox;

      transaction.set(userRef, userUpdates, { merge: true });
    });

    // 4. Set Custom Claims for instant identity verification
    try {
      await admin.auth().setCustomUserClaims(uid, { role: 'client' });
    } catch (claimErr) {
      console.warn('[LicenseRedeem] Custom claims update notice:', claimErr.message);
    }

    return res.status(200).json({
      success: true,
      message: 'License key redeemed successfully. 48-hour entitlement activated.',
      licenseKey: cleanKey,
      assignedMailbox,
      mailboxType
    });

  } catch (err) {
    if (err.message === 'LICENSE_NOT_FOUND') {
      return res.status(404).json({ success: false, error: 'Invalid license key. Document not found.' });
    }
    if (err.message === 'LICENSE_ALREADY_REDEEMED') {
      return res.status(409).json({ success: false, error: 'This license key has already been redeemed or revoked.' });
    }
    console.error('[LicenseRedeem] Transaction error:', err);
    return res.status(500).json({ success: false, error: 'Internal error processing license redemption.' });
  }
});

// =========================================================================
// 7.1 Single-Use Burn-Before-Creation Signup Architecture
// SEC-CRIT-02 Remediation: Key is atomically locked/burned BEFORE Auth creation.
// Eliminates duplicate accounts, race conditions, and orphan auth entries.
// =========================================================================
router.post('/api/v1/license/signup', async (req, res) => {
  try {
    const { licenseKey, email, password, name, mobile, instagramId, dpdpConsent } = req.body || {};

    if (!licenseKey || typeof licenseKey !== 'string') {
      return res.status(400).json({ success: false, error: 'Please enter a valid License Key.' });
    }
    const cleanKey = licenseKey.trim();
    if (!cleanKey) {
      return res.status(400).json({ success: false, error: 'Please enter a valid License Key.' });
    }

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ success: false, error: 'Please enter a valid email address.' });
    }
    const cleanEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      return res.status(400).json({ success: false, error: 'Please enter a valid email address.' });
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters.' });
    }

    if (!dpdpConsent) {
      return res.status(400).json({ success: false, error: 'You must agree to the Privacy Policy and DPDP consent to register.' });
    }

    if (!db) {
      return res.status(500).json({ success: false, error: 'Firestore database uninitialized.' });
    }

    // 1. Check if user already exists in Firebase Auth
    let existingAuthUser = null;
    try {
      existingAuthUser = await admin.auth().getUserByEmail(cleanEmail);
    } catch (e) {
      if (e.code !== 'auth/user-not-found') {
        console.warn('[LicenseSignup] Auth lookup warning:', e.message);
      }
    }

    if (existingAuthUser) {
      const existingProfileSnap = await db.collection('users').doc(existingAuthUser.uid).get();
      if (existingProfileSnap.exists) {
        return res.status(400).json({ 
          success: false, 
          error: 'This email address is already registered. Please sign in directly.' 
        });
      }
    }

    const keyRef = db.collection('license_keys').doc(cleanKey);
    let assignedMailbox = null;
    let mailboxType = null;
    const now = new Date();
    const expiry = new Date(now.getTime() + 48 * 60 * 60 * 1000); // 48-hour entitlement

    // 2. ATOMIC FIRESTORE TRANSACTION: Burn key BEFORE any account is created!
    // Ensures strictly 1 key = 1 account. Any concurrent race fails here with 409 Conflict.
    await db.runTransaction(async (transaction) => {
      const keyDoc = await transaction.get(keyRef);
      if (!keyDoc.exists) {
        throw new Error('LICENSE_NOT_FOUND');
      }

      const keyData = keyDoc.data();
      if (keyData.status !== 'active') {
        throw new Error('LICENSE_ALREADY_REDEEMED');
      }

      if (keyData.redeemedBy || keyData.usedBy) {
        throw new Error('LICENSE_ALREADY_REDEEMED');
      }

      assignedMailbox = keyData.assignedMailbox || null;
      mailboxType = keyData.mailboxType || null;

      // Atomically burn key immediately
      transaction.update(keyRef, {
        status: 'redeemed',
        redeemedByEmail: cleanEmail,
        redeemedAt: admin.firestore.FieldValue.serverTimestamp(),
        burnPhase: 'burn_before_creation'
      });
    });

    // 3. Key is successfully burned. Now proceed with Auth Account Creation
    let user;
    try {
      if (existingAuthUser) {
        user = existingAuthUser;
        await admin.auth().updateUser(user.uid, {
          password: password,
          displayName: (name || '').trim()
        });
      } else {
        user = await admin.auth().createUser({
          email: cleanEmail,
          password: password,
          displayName: (name || '').trim()
        });
      }
    } catch (authCreateErr) {
      // ROLLBACK SAFETY NET: If Auth account creation fails, rollback key status to 'active'
      console.error('[LicenseSignup] Auth creation failed after burn, executing rollback:', authCreateErr.message);
      try {
        await keyRef.update({
          status: 'active',
          redeemedByEmail: null,
          redeemedAt: null,
          burnPhase: null
        });
        await db.collection('audit_logs').add({
          event: 'LICENSE_SIGNUP_ROLLBACK',
          keyHash: crypto.createHash('sha256').update(cleanKey).digest('hex'),
          email: cleanEmail,
          reason: authCreateErr.message,
          timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
      } catch (rbErr) {
        console.error('[LicenseSignup] Critical rollback failure:', rbErr);
      }
      return res.status(400).json({ 
        success: false, 
        error: authCreateErr.message || 'Failed to create authentication account.' 
      });
    }

    const uid = user.uid;

    // 4. Update Key with final UID, write User Profile and Subscriptions using Admin batch
    let cleanInstaUser = '';
    let cleanInstaLink = '';
    if (instagramId && typeof instagramId === 'string') {
      let str = instagramId.trim().replace(/^(?:https?:\/\/)?(?:www\.)?(?:instagram\.com\/)?/, '').replace(/^[@/]+/, '');
      const match = str.match(/^([a-zA-Z0-9._-]+)/);
      cleanInstaUser = match ? match[1] : '';
      cleanInstaLink = cleanInstaUser ? `https://instagram.com/${cleanInstaUser}` : '';
    }

    const userProfile = {
      uid: uid,
      name: (name || '').trim(),
      email: cleanEmail,
      mobile: (mobile || '').trim(),
      instagramId: cleanInstaUser,
      instagram_link: cleanInstaLink,
      role: 'client',
      status: 'active',
      createdAt: now.toISOString(),
      usedLicenseKey: cleanKey,
      dpdpConsentGiven: true,
      dpdpConsentTimestamp: now.toISOString(),
      dpdpConsentVersion: 'v1.0-sept2026'
    };

    if (mailboxType === 'gmail' && assignedMailbox) userProfile.linkedGmail = assignedMailbox;
    if (mailboxType === 'zoho' && assignedMailbox) userProfile.linkedZoho = assignedMailbox;
    if (mailboxType === 'imap' && assignedMailbox) userProfile.linkedImap = assignedMailbox;

    const userRef = db.collection('users').doc(uid);
    const subRef = db.collection('subscriptions').doc(uid);

    const finalBatch = db.batch();
    finalBatch.set(userRef, userProfile);
    finalBatch.update(keyRef, {
      status: 'redeemed',
      redeemedBy: uid,
      redeemedByEmail: cleanEmail,
      redeemedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    finalBatch.set(subRef, {
      productName: 'License Key Activation',
      purchaseDate: now.toISOString(),
      expiryDate: expiry.toISOString(),
      validityDays: 2,
      amountPaid: 0,
      status: 'Active',
      notes: `Activated via License Key: ${cleanKey}`,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await finalBatch.commit();

    // 5. Authoritative Custom Claims
    try {
      await admin.auth().setCustomUserClaims(uid, { role: 'client' });
    } catch (claimErr) {
      console.warn('[LicenseSignup] Custom claims notice:', claimErr.message);
    }

    // 6. Create custom token for automatic client authentication
    const customToken = await admin.auth().createCustomToken(uid);

    return res.status(200).json({
      success: true,
      message: 'Account registered successfully! Welcome.',
      customToken,
      uid,
      email: cleanEmail,
      assignedMailbox,
      mailboxType
    });

  } catch (err) {
    if (err.message === 'LICENSE_NOT_FOUND') {
      return res.status(404).json({ success: false, error: 'Invalid License Key. Please contact the administrator.' });
    }
    if (err.message === 'LICENSE_ALREADY_REDEEMED') {
      return res.status(409).json({ success: false, error: 'This License Key is invalid, expired, or has already been claimed.' });
    }
    console.error('[LicenseSignup] Transaction error:', err);
    return res.status(500).json({ success: false, error: 'Internal error processing license registration.' });
  }
});

// =========================================================================
// 8. Secure Backend Google OAuth Exchange (Removes Secret from Client APKs)
// =========================================================================
router.post('/api/v1/auth/google-oauth-exchange', verifyFirebaseAuth, async (req, res) => {
  try {
    const { code, redirectUri } = req.body;
    if (!code) {
      return res.status(400).json({ success: false, error: 'Authorization code is required.' });
    }

    let clientId = process.env.VITE_GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID;
    let clientSecret = process.env.VITE_GOOGLE_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET;

    if ((!clientId || !clientSecret) && db) {
      try {
        const oauthDoc = await db.collection('system_settings').doc('google_oauth').get();
        if (oauthDoc.exists) {
          const oauthData = oauthDoc.data();
          clientId = clientId || oauthData.clientId || oauthData.client_id;
          clientSecret = clientSecret || oauthData.clientSecret || oauthData.client_secret;
        }
      } catch (err) {
        console.warn('[GoogleOAuthExchange] Firestore settings read warning:', err.message);
      }
    }

    if (!clientId || !clientSecret) {
      return res.status(500).json({ success: false, error: 'Google OAuth credentials not configured on the server.' });
    }

    const params = new URLSearchParams();
    params.append('code', code);
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('grant_type', 'authorization_code');
    if (redirectUri) {
      params.append('redirect_uri', redirectUri);
    }

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
      if (redirectUri) {
        params.delete('redirect_uri');
        const retryRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params.toString()
        });
        const retryData = await retryRes.json();
        if (retryRes.ok) {
          return res.status(200).json({
            success: true,
            accessToken: retryData.access_token,
            refreshToken: retryData.refresh_token || retryData.access_token
          });
        }
      }
      return res.status(400).json({ success: false, error: tokenData.error_description || 'OAuth exchange failed' });
    }

    return res.status(200).json({
      success: true,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token || tokenData.access_token
    });
  } catch (err) {
    console.error('[GoogleOAuthExchange] Error:', err);
    return res.status(500).json({ success: false, error: 'Failed to exchange authorization code.' });
  }
});

// =========================================================================
// 9. Secure Google OAuth Token Refresh (Phase 3c Remediation)
// Refresh tokens are processed server-side; client secret is never exposed in browser
// =========================================================================
router.post('/api/v1/auth/google-refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ success: false, error: 'refreshToken is required.' });
    }

    let clientId = process.env.VITE_GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID;
    let clientSecret = process.env.VITE_GOOGLE_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET;

    if ((!clientId || !clientSecret) && db) {
      try {
        const oauthDoc = await db.collection('system_settings').doc('google_oauth').get();
        if (oauthDoc.exists) {
          const oauthData = oauthDoc.data();
          clientId = clientId || oauthData.clientId || oauthData.client_id;
          clientSecret = clientSecret || oauthData.clientSecret || oauthData.client_secret;
        }
      } catch (err) {
        console.warn('[GoogleRefreshToken] Firestore settings read warning:', err.message);
      }
    }

    if (!clientId || !clientSecret) {
      return res.status(500).json({ success: false, error: 'Google OAuth credentials not configured on the server.' });
    }

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(tokenRes.status || 400).json({
        success: false,
        error: tokenData.error_description || tokenData.error || 'Token refresh failed'
      });
    }

    return res.status(200).json({
      success: true,
      accessToken: tokenData.access_token,
      expiresIn: tokenData.expires_in
    });
  } catch (err) {
    console.error('[GoogleRefreshToken] Error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// =========================================================================
// Dedicated Android App Payment Proxy Endpoints (Supabase Backend Core)
// Holds PAYMENT_CORE_API_KEY server-side. No Origin header sent.
// =========================================================================

// POST /payments/create-order & /api/v1/payments/create-order
// Accepts { amount_paise } from authenticated app user.
// Returns ONLY { ref, payable_amount, upi_uri, qr_svg, expires_at }.
router.post(['/payments/create-order', '/api/v1/payments/create-order'], verifyFirebaseAuth, async (req, res) => {
  try {
    const rawAmount = req.body?.amount_paise ?? (req.body?.amount ? Math.round(Number(req.body.amount) * 100) : null);
    const amountPaise = parseInt(rawAmount, 10);

    if (isNaN(amountPaise) || amountPaise <= 0) {
      return res.status(400).json({ error: 'invalid_amount', message: 'amount_paise must be a positive integer in paise' });
    }

    const apiKey = process.env.PAYMENT_CORE_API_KEY;
    if (!apiKey) {
      console.error('[Payments Proxy] Missing PAYMENT_CORE_API_KEY env var');
      return res.status(500).json({ error: 'config_error', message: 'Payment gateway configuration is missing' });
    }

    const sbRes = await fetch('https://voncpwijuctbfiqictcp.supabase.co/functions/v1/api/orders', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey
      },
      body: JSON.stringify({ amount_paise: amountPaise })
    });

    if (!sbRes.ok) {
      const errText = await sbRes.text().catch(() => '');
      console.error('[Payments Proxy] Supabase create-order failed:', sbRes.status, errText);
      return res.status(sbRes.status).json({ error: 'payment_gateway_error', message: 'Failed to create order with payment gateway' });
    }

    const data = await sbRes.json();

    // Optionally sync created order with Firestore for account history
    try {
      if (db && data.ref) {
        const userId = req.uid || req.user?.uid || null;
        const itemId = req.body?.itemId || null;
        await db.collection('orders').doc(data.ref).set({
          orderCode: data.ref,
          ref: data.ref,
          userId,
          itemId,
          amount: Math.round(amountPaise / 100),
          amountPaise,
          payableAmount: data.payable_amount,
          exactPayable: data.payable_amount,
          upiUri: data.upi_uri,
          expiresAt: data.expires_at,
          status: 'PENDING',
          isSupabaseCore: true,
          createdAt: new Date().toISOString()
        }, { merge: true });
      }
    } catch (fsErr) {
      console.warn('[Payments Proxy] Firestore sync note:', fsErr.message);
    }

    // Return ONLY { ref, payable_amount, upi_uri, qr_svg, expires_at } as strictly specified
    return res.status(200).json({
      ref: data.ref,
      payable_amount: data.payable_amount,
      upi_uri: data.upi_uri,
      qr_svg: data.qr_svg,
      expires_at: data.expires_at
    });
  } catch (err) {
    console.error('[Payments Proxy] Create Order Exception:', err.message);
    return res.status(500).json({ error: 'server_error', message: 'Internal server error creating payment order' });
  }
});

// GET /payments/status/:ref & /api/v1/payments/status/:ref
// Forwards to Supabase GET /orders/{ref} with PAYMENT_CORE_API_KEY.
// Returns ONLY { status, payable_amount, expires_at, paid_at }.
router.get(['/payments/status/:ref', '/api/v1/payments/status/:ref'], async (req, res) => {
  try {
    const rawRef = req.params?.ref ? String(req.params.ref).trim() : '';
    if (!rawRef || !/^[A-Za-z0-9_-]+$/.test(rawRef)) {
      return res.status(400).json({ error: 'invalid_ref', message: 'Order reference format is invalid' });
    }

    const apiKey = process.env.PAYMENT_CORE_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'config_error', message: 'Payment gateway configuration is missing' });
    }

    const sbRes = await fetch(`https://voncpwijuctbfiqictcp.supabase.co/functions/v1/api/orders/${encodeURIComponent(rawRef)}`, {
      method: 'GET',
      headers: {
        'x-api-key': apiKey
      }
    });

    if (!sbRes.ok) {
      return res.status(sbRes.status).json({ error: 'order_not_found', message: 'Order reference not found' });
    }

    const data = await sbRes.json();

    // If order was paid, reflect it in Firestore too
    if (data.status === 'PAID') {
      try {
        if (db) {
          await db.collection('orders').doc(rawRef).set({
            status: 'PAID',
            paidAt: data.paid_at || new Date().toISOString()
          }, { merge: true });
        }
      } catch (updateErr) {
        console.warn('[Payments Proxy] Order status sync note:', updateErr.message);
      }
    }

    // Return ONLY { status, payable_amount, expires_at } (+ paid_at)
    return res.status(200).json({
      status: data.status,
      payable_amount: data.payable_amount,
      expires_at: data.expires_at,
      paid_at: data.paid_at || null
    });
  } catch (err) {
    console.error('[Payments Proxy] Status Check Exception:', err.message);
    return res.status(500).json({ error: 'server_error', message: 'Internal server error checking payment status' });
  }
});

export default router;

