// constants.ts

export const Delimiters = {
    // ASCII char: `{`
    START_BRACE: 123,
    // ASCII char: `}`
    END_BRACE: 125,
    // ASCII char `[`
    START_BRACKET: 91,
    // ASCII char `]`
    END_BRACKET: 93,
    // ASCII char `"`
    QUOTE: 34,
    // ASCII char `:`
    COLON: 58,
    // ASCII char `,`
    COMMA: 44,
};

export const WhiteSpace = {
    // ASCII char: `\n`
    NEWLINE: 10,
    // ASCII char: ` `
    SPACE: 32,
};

export const Numbers = {
    ZERO: 48,
    ONE: 49,
    TWO: 50,
    THREE: 51,
    FOUR: 52,
    FIVE: 53,
    SIX: 54,
    SEVEN: 55,
    EIGHT: 56,
    NINE: 57
}

export const Escape = {
    // ASCII char: `\`
    BACKSLASH: 92,
};

export const INITIAL_IN = {
    byte: 0,
    stack: [[0, 0], [0, 0], [0, 0], [0, 0]],
    parsing_string: 0,
    parsing_number: 0,
};

export const INITIAL_OUT = {
    next_stack: INITIAL_IN.stack,
    next_parsing_string: INITIAL_IN.parsing_string,
    next_parsing_number: INITIAL_IN.parsing_number,
};