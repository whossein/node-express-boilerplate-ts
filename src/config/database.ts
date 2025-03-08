import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';

dotenv.config();

const sequelize = new Sequelize({
  dialect: 'mysql',
  host: process.env.DB_HOST || 'localhost',
  username: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'test_db',
  port: parseInt(process.env.DB_PORT || '3306'),
  logging: console.log,
});

const testConnection = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ MySQL connection has been established successfully.');
    return true;
  } catch (error) {
    console.error('❌ Unable to connect to the MySQL database:', error);
    return false;
  }
};

export { sequelize, testConnection };
