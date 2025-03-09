import { Model, DataTypes, Optional } from 'sequelize';
import { sequelize } from '../config/database';
import { tokenTypes } from '../config/tokens';
import User from './user.model';

export interface TokenAttributes {
  id: number;
  token: string;
  userId: number;
  type: tokenTypes;
  expires: Date;
  blacklisted: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface TokenInput extends Optional<TokenAttributes, 'id' | 'blacklisted' | 'createdAt' | 'updatedAt'> {}
export interface TokenOutput extends Required<TokenAttributes> {}

class Token extends Model<TokenAttributes, TokenInput> implements TokenAttributes {
  public id!: number;
  public token!: string;
  public userId!: number;
  public type!: tokenTypes;
  public expires!: Date;
  public blacklisted!: boolean;

  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;

  // Declare association
  public readonly user?: User;
}

Token.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    token: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'Users',
        key: 'id',
      },
    },
    type: {
      type: DataTypes.ENUM(...Object.values(tokenTypes)),
      allowNull: false,
    },
    expires: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    blacklisted: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    createdAt: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    updatedAt: {
      type: DataTypes.DATE,
      allowNull: false,
    },
  },
  {
    sequelize,
    modelName: 'Token',
    tableName: 'Tokens',
    indexes: [
      {
        fields: ['token'],
      },
      {
        fields: ['userId'],
      },
    ],
  },
);

// Define association
Token.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user',
});

export default Token;
