'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { validatePassword, MIN_LENGTH } = require('../utils/passwordPolicy');

describe('validatePassword', () => {
  it('rejects short passwords', () => {
    const r = validatePassword('Ab1');
    assert.equal(r.ok, false);
    assert.match(r.error, new RegExp(String(MIN_LENGTH)));
  });

  it('requires mixed case and a digit', () => {
    assert.equal(validatePassword('alllowercase1').ok, false);
    assert.equal(validatePassword('ALLUPPERCASE1').ok, false);
    assert.equal(validatePassword('NoNumbersHere').ok, false);
  });

  it('accepts valid passwords', () => {
    assert.equal(validatePassword('SecurePass1').ok, true);
  });
});
