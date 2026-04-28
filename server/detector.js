'use strict';

// Thin proxy — keeps existing require('./detector') imports working.
// All logic lives in detector/
module.exports = require('./detector/index');
