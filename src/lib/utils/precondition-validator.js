const ValidationError = require('./validation-error');

class PreconditionValidator {
  static shouldNotBeEmpty(value, fieldName = 'N/A') {
    if (
      Object.is(value, undefined) ||
      Object.is(value, null) ||
      Object.is(value, '') ||
      (typeof value === 'string' && value.trim().length === 0)
    ) {
      throw new ValidationError(`The provided value \`${value}\` for ${fieldName} field should not be empty.`);
    }
    return PreconditionValidator;
  }

  static shouldBeEnumType(value, options) {
    if (options.indexOf(value) < 0) {
      throw new ValidationError(
        `The provided value \`${value}\` should be one of the enumeration: ${options.join(' ,')}.`
      );
    }
    return PreconditionValidator;
  }

  static shouldBeValidDateString(value) {
    if (Number.isNaN(new Date(value).getTime())) {
      throw new ValidationError(`The provided value \`${value}\` should be a valid timestamp.`);
    }
    return PreconditionValidator;
  }

  static shouldBeArrayOrArrayText(input) {
    let array = input;

    if (typeof array === 'string') {
      try {
        array = JSON.parse(array);
      } catch (_err) {
        throw new _err();
      }
    }

    if (!Array.isArray(array)) {
      throw new ValidationError(`The provided value \`${input}\` should be an array or an array text.`);
    }

    for (const element of array) {
      PreconditionValidator.shouldNotBeEmpty(element);
    }

    return PreconditionValidator;
  }
}

module.exports = exports = PreconditionValidator;
