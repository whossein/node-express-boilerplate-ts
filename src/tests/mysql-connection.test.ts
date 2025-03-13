import { testConnection } from '../config/database';

const runTest = async () => {
  console.log('🔄 Testing MySQL connection...');
  await testConnection();
  process.exit();
};

runTest();
