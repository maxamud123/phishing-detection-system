import { describe, it, expect } from 'vitest';
import { validatePassword, MIN_PASSWORD_LENGTH } from './passwordPolicy';

describe('validatePassword', () => {
  it('requires minimum length', () => {
    expect(validatePassword('Ab1')).toMatch(/at least/);
    expect(validatePassword('Aa1')).toMatch(/at least/);
  });

  it('requires upper, lower, and number', () => {
    expect(validatePassword('alllowercase1')).toMatch(/uppercase/);
    expect(validatePassword('ALLUPPERCASE1')).toMatch(/lowercase/);
    expect(validatePassword('NoNumbersHere')).toMatch(/number/);
  });

  it('accepts strong passwords', () => {
    expect(validatePassword('SecurePass1')).toBeNull();
  });
});
