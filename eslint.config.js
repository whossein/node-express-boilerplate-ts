const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  {
    ignores: ['node_modules/**', 'bin/**', 'migrations/**', 'models/**', 'src/migrations/**'],
    languageOptions: {
      globals: {
        require: true,
        module: true,
        __dirname: true,
        __filename: true,
      },
      ecmaVersion: 2022,
      sourceType: 'commonjs',
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
];
