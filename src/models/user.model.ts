import { Model, DataTypes } from 'sequelize';
import bcrypt from 'bcryptjs';
import sequelize from '../config/database';

interface UserAttributes {
  id: number;
  name: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  isEmailVerified: boolean;
}

class User extends Model<UserAttributes> implements UserAttributes {
  public id!: number;
  public name!: string;
  public email!: string;
  public password!: string;
  public role!: 'user' | 'admin';
  public isEmailVerified!: boolean;

  // timestamps
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;

  public async isPasswordMatch(password: string): Promise<boolean> {
    return bcrypt.compare(password, this.password);
  }
}

User.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
      type: DataTypes.ENUM('user', 'admin'),
      defaultValue: 'user',
    },
    isEmailVerified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
  },
  {
    sequelize,
    modelName: 'User',
    hooks: {
      beforeSave: async (user: User) => {
        if (user.changed('password')) {
          user.password = await bcrypt.hash(user.password, 8);
        }
      },
    },
  },
);

export default User;
