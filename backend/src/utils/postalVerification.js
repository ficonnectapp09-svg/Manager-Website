/**
 * Connect App Ecosystem - Authoritative Indian Postal PIN Code Verification
 * Verifies 6-digit Indian PIN Codes against the official India Post Postal Directory
 * and checks compatibility with selected State and District.
 */

const https = require('https');
const http = require('http');
const db = require('../config/db');

// In-memory cache for verified postal records (TTL: 24 hours)
const postalCache = new Map();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

// Alternate name mappings for Indian states & districts (administrative revenue vs postal names)
const TERRITORY_ALIASES = {
  // States
  'tamilnadu': ['tamil nadu', 'tn'],
  'tamil nadu': ['tamilnadu', 'tn'],
  'pondicherry': ['puducherry', 'py'],
  'puducherry': ['pondicherry', 'py'],
  'karnataka': ['kar', 'ka'],
  'gujarat': ['guj', 'gj'],
  'orissa': ['odisha'],
  'odisha': ['orissa'],
  
  // Districts & Divisions
  'bangalore': ['bengaluru', 'bangalore urban', 'bangalore rural', 'bangalore gpo', 'bangalore east', 'bangalore north', 'bangalore south', 'bangalore west'],
  'bengaluru': ['bangalore', 'bengaluru urban', 'bengaluru rural', 'bangalore urban', 'bangalore rural'],
  'bengaluru urban': ['bangalore', 'bengaluru', 'bangalore urban'],
  'bengaluru rural': ['bangalore', 'bengaluru', 'bangalore rural'],
  'salem': ['salem west', 'salem east', 'salem south'],
  'salem west': ['salem'],
  'salem east': ['salem'],
  'krishnagiri': ['hosur', 'dharmapuri'],
  'dharmapuri': ['hosur', 'krishnagiri'],
  'hosur': ['krishnagiri', 'dharmapuri'],
  'belgaum': ['belagavi'],
  'belagavi': ['belgaum'],
  'bellary': ['ballari'],
  'ballari': ['bellary'],
  'mysore': ['mysuru'],
  'mysuru': ['mysore'],
  'hubli': ['hubballi', 'dharwad'],
  'hubballi': ['hubli', 'dharwad'],
  'mangalore': ['mangaluru', 'dakshina kannada'],
  'mangaluru': ['mangalore', 'dakshina kannada'],
  'bijapur': ['vijayapura'],
  'vijayapura': ['bijapur'],
  'gulbarga': ['kalaburagi'],
  'kalaburagi': ['gulbarga'],
  'shimoga': ['shivamogga'],
  'shivamogga': ['shimoga'],
  'baroda': ['vadodara'],
  'vadodara': ['baroda'],
  'ahmedabad': ['ahmedabad city', 'ahmedabad rural'],
  'bombay': ['mumbai', 'mumbai suburban'],
  'mumbai': ['bombay', 'mumbai suburban', 'mumbai city'],
  'madras': ['chennai'],
  'chennai': ['madras'],
  'calcutta': ['kolkata'],
  'kolkata': ['calcutta'],
  'gurgaon': ['gurugram'],
  'gurugram': ['gurgaon'],
  'calicut': ['kozhikode'],
  'kozhikode': ['calicut'],
  'cochin': ['kochi', 'ernakulam'],
  'kochi': ['cochin', 'ernakulam'],
  'trivandrum': ['thiruvananthapuram'],
  'thiruvananthapuram': ['trivandrum'],
  'kanyakumari': ['kanniyakumari'],
  'kanniyakumari': ['kanyakumari'],
  'tirunelveli': ['nellai'],
  'nellai': ['tirunelveli'],
  'tuticorin': ['thoothukudi'],
  'thoothukudi': ['tuticorin']
};

/**
 * Normalizes location strings for comparison:
 * Lowercases, strips punctuation, normalizes whitespace.
 */
function normalizeString(str) {
  if (!str) return '';
  return String(str)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Checks whether an entered territory name matches a postal territory name.
 */
function matchesTerritory(entered, postal) {
  if (!entered || !postal) return true; // if not provided, don't block
  const normEntered = normalizeString(entered);
  const normPostal = normalizeString(postal);

  if (!normEntered || !normPostal) return true;
  if (normEntered === normPostal) return true;

  // Partial substring matches (e.g. "Salem" in "Salem West", "Bengaluru" in "Bengaluru Urban")
  if (normPostal.includes(normEntered) || normEntered.includes(normPostal)) return true;

  // Compressed comparison without spaces (e.g. "tamilnadu" vs "tamil nadu")
  const compEntered = normEntered.replace(/\s/g, '');
  const compPostal = normPostal.replace(/\s/g, '');
  if (compEntered === compPostal) return true;
  if (compPostal.includes(compEntered) || compEntered.includes(compPostal)) return true;

  // Check alias dictionary
  const enteredAliases = TERRITORY_ALIASES[normEntered] || TERRITORY_ALIASES[compEntered] || [];
  if (enteredAliases.some(alias => {
    const normAlias = normalizeString(alias);
    const compAlias = normAlias.replace(/\s/g, '');
    return normAlias === normPostal || compAlias === compPostal || normPostal.includes(normAlias) || normAlias.includes(normPostal);
  })) {
    return true;
  }

  const postalAliases = TERRITORY_ALIASES[normPostal] || TERRITORY_ALIASES[compPostal] || [];
  if (postalAliases.some(alias => {
    const normAlias = normalizeString(alias);
    const compAlias = normAlias.replace(/\s/g, '');
    return normAlias === normEntered || compAlias === compEntered || normEntered.includes(normAlias) || normAlias.includes(normEntered);
  })) {
    return true;
  }

  return false;
}

/**
 * Performs HTTP/HTTPS GET request with timeout to fetch JSON
 */
function fetchJsonWithTimeout(url, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, { headers: { 'User-Agent': 'ConnectApp-PostalVerification/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`HTTP ${res.statusCode}`));
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

/**
 * Queries India Post postal directory for the given 6-digit PIN code.
 */
async function queryPostalDirectory(pincode) {
  // 1. Check in-memory cache
  const cached = postalCache.get(pincode);
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL_MS)) {
    return cached.data;
  }

  // 2. Query official India Post public directory API
  try {
    const url = `https://api.postalpincode.in/pincode/${pincode}`;
    const response = await fetchJsonWithTimeout(url, 4000);

    if (Array.isArray(response) && response[0]) {
      const result = response[0];
      if (result.Status === 'Success' && Array.isArray(result.PostOffice) && result.PostOffice.length > 0) {
        const postOffices = result.PostOffice.map(po => ({
          name: po.Name ? po.Name.trim() : '',
          branchType: po.BranchType || '',
          deliveryStatus: po.DeliveryStatus || '',
          circle: po.Circle || '',
          district: po.District ? po.District.trim() : '',
          division: po.Division ? po.Division.trim() : '',
          region: po.Region || '',
          state: po.State ? po.State.trim() : '',
          country: po.Country || 'India',
          pincode: po.Pincode || pincode
        }));

        const primaryPo = postOffices.find(po => po.deliveryStatus === 'Delivery') || postOffices[0];
        const data = {
          exists: true,
          pincode,
          postOffices,
          primaryPostOffice: primaryPo?.name || '',
          district: primaryPo?.district || '',
          division: primaryPo?.division || '',
          state: primaryPo?.state || '',
          circle: primaryPo?.circle || ''
        };

        postalCache.set(pincode, { timestamp: Date.now(), data });
        return data;
      } else if (result.Status === 'Error' || (result.Message && result.Message.toLowerCase().includes('no records found'))) {
        const data = { exists: false, pincode, message: 'This PIN Code does not exist in the verified postal directory.' };
        postalCache.set(pincode, { timestamp: Date.now(), data });
        return data;
      }
    }
  } catch (apiErr) {
    console.warn(`[PostalVerification] External API lookup failed for PIN ${pincode}: ${apiErr.message}`);
  }

  // 3. Fallback: Query MongoDB territory master data in database
  try {
    if (db && db.pincodes) {
      const dbPincodes = await db.pincodes.find({
        $or: [{ code: pincode }, { pincode }]
      });

      if (dbPincodes && dbPincodes.length > 0) {
        const first = dbPincodes[0];
        let stateName = first.state || first.stateName || null;
        let districtName = first.district || first.districtName || null;

        if (!stateName && first.stateId && db.states) {
          const st = await db.states.findById(first.stateId);
          if (st) stateName = st.name;
        }
        if (!districtName && first.districtId && db.districts) {
          const dt = await db.districts.findById(first.districtId);
          if (dt) districtName = dt.name;
        }

        const postOffices = dbPincodes.map(p => ({
          name: p.name || p.areaName || 'Main Post Office',
          branchType: 'Sub Post Office',
          deliveryStatus: 'Delivery',
          district: districtName || '',
          state: stateName || '',
          pincode
        }));

        const data = {
          exists: true,
          pincode,
          postOffices,
          primaryPostOffice: postOffices[0]?.name || '',
          district: districtName || '',
          state: stateName || '',
          isLocalDbMatch: true
        };

        postalCache.set(pincode, { timestamp: Date.now(), data });
        return data;
      }
    }
  } catch (dbErr) {
    console.warn(`[PostalVerification] Database fallback lookup error: ${dbErr.message}`);
  }

  // If both external API and local lookup could not prove existence
  return {
    exists: false,
    pincode,
    isUnavailable: true,
    message: 'Unable to verify PIN Code right now. Please try again.'
  };
}

/**
 * Main verification function:
 * Validates format, queries India Post directory, and verifies State and District compatibility.
 * 
 * @param {string} pincode - 6-digit PIN code
 * @param {string} [state] - Entered or selected State name
 * @param {string} [district] - Entered or selected District name
 * @returns {Promise<Object>} Verification result
 */
async function verifyIndianPostalPincode(pincode, state = '', district = '') {
  // Step 1: Format Validation
  if (!pincode || typeof pincode !== 'string' && typeof pincode !== 'number') {
    return {
      isValid: false,
      formatValid: false,
      code: 'INVALID_FORMAT',
      message: 'Enter a valid 6-digit Indian PIN Code.'
    };
  }

  const cleanPin = String(pincode).trim().replace(/\D/g, '');

  if (!/^[1-9][0-9]{5}$/.test(cleanPin)) {
    return {
      isValid: false,
      formatValid: false,
      code: 'INVALID_FORMAT',
      message: 'Enter a valid 6-digit Indian PIN Code.'
    };
  }

  // Step 2: Authoritative Directory Existence Check
  const lookup = await queryPostalDirectory(cleanPin);

  if (!lookup || lookup.isUnavailable) {
    return {
      isValid: false,
      formatValid: true,
      exists: false,
      code: 'LOOKUP_FAILED',
      message: 'Unable to verify PIN Code right now. Please try again.'
    };
  }

  if (!lookup.exists) {
    return {
      isValid: false,
      formatValid: true,
      exists: false,
      code: 'PIN_NOT_FOUND',
      message: 'This PIN Code does not exist in the verified postal directory.'
    };
  }

  // Step 3: State & District Compatibility Matching
  const verifiedState = lookup.state || '';
  const verifiedDistrict = lookup.district || '';
  const verifiedDivision = lookup.division || '';

  // Check State compatibility if state is provided
  if (state && String(state).trim()) {
    const isStateMatch = matchesTerritory(state, verifiedState);
    if (!isStateMatch) {
      return {
        isValid: false,
        formatValid: true,
        exists: true,
        stateMismatch: true,
        code: 'STATE_MISMATCH',
        enteredState: state,
        verifiedState,
        verifiedDistrict,
        postOffices: lookup.postOffices,
        message: `This PIN Code belongs to ${verifiedState}, not ${state}.`
      };
    }
  }

  // Check District compatibility if district is provided
  if (district && String(district).trim()) {
    const isDistrictMatch = matchesTerritory(district, verifiedDistrict) || 
                            matchesTerritory(district, verifiedDivision);
    if (!isDistrictMatch) {
      return {
        isValid: false,
        formatValid: true,
        exists: true,
        districtMismatch: true,
        code: 'DISTRICT_MISMATCH',
        enteredDistrict: district,
        verifiedDistrict,
        verifiedState,
        postOffices: lookup.postOffices,
        message: `This PIN Code does not belong to the selected district.`
      };
    }
  }

  // All checks passed!
  return {
    isValid: true,
    formatValid: true,
    exists: true,
    pincode: cleanPin,
    state: verifiedState,
    district: verifiedDistrict,
    division: verifiedDivision,
    primaryPostOffice: lookup.primaryPostOffice,
    postOffices: lookup.postOffices,
    message: `Verified India Post: ${lookup.primaryPostOffice ? lookup.primaryPostOffice + ', ' : ''}${verifiedDistrict}, ${verifiedState}`
  };
}

module.exports = {
  verifyIndianPostalPincode,
  queryPostalDirectory,
  matchesTerritory,
  normalizeString
};
