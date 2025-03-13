import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../config/database';
import { tokenTypes } from '../config/tokens';
import User from './user.model';

interface TokenAttributes {
  id: number;
  token: string;
  userId: number;
  type: tokenTypes;
  expires: Date;
  blacklisted: boolean;
}

class Token extends Model<TokenAttributes> implements TokenAttributes {
  public id!: number;
  public token!: string;
  public userId!: number;
  public type!: tokenTypes;
  public expires!: Date;
  public blacklisted!: boolean;

  // timestamps
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;
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
  },
  {
    sequelize,
    modelName: 'Token',
    indexes: [
      {
        fields: ['token'],
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
