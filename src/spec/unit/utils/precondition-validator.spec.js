const PreconditionValidator = require('../../../lib/utils/precondition-validator');

describe('Precondition validator', function() {
  let value;

  it('should be chainable', () => {
    expect(() => {
      PreconditionValidator.shouldNotBeEmpty('abc123')
        .shouldBeEnumType('option1', ['option1'])
        .shouldBeValidDateString(new Date().toISOString())
        .shouldBeArrayOrArrayText([1, 2, 3]);
    }).to.not.throw();
  });

  it('can validate whether a value is empty :: shouldNotBeEmpty()', () => {
    value = '  ';

    expect(() => {
      PreconditionValidator.shouldNotBeEmpty(value);
    }).to.throw();
  });

  it('can validate if a value belongs to one of the provided options :: shouldBeEnumType()', () => {
    value = 'option2';

    expect(() => {
      PreconditionValidator.shouldBeEnumType(value, [value]);
    }).to.not.throw();
  });

  it('can validate if a value is a valid time :: shouldBeValidTime()', () => {
    value = new Date().toISOString();

    expect(() => {
      PreconditionValidator.shouldBeValidDateString(value);
    }).to.not.throw();
  });

  context('can validate if a value is an array :: shouldBeArrayOrArrayText()', () => {
    it('after parsing', () => {
      value = [4, 5, 6];

      expect(() => {
        PreconditionValidator.shouldBeArrayOrArrayText(value);
      }).to.not.throw();
    });

    it('before parsing', () => {
      value = JSON.stringify([7, 8, 9]);

      expect(() => {
        PreconditionValidator.shouldBeArrayOrArrayText(value);
      }).to.not.throw();
    });
  });
});
