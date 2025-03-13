import httpStatus from 'http-status';
import { User } from '../models';
import { ApiError } from '../utils';
import { WhereOptions, FindOptions, Op } from 'sequelize';
import type { UserAttributes } from '../models/user.model';

interface PaginationOptions {
  limit?: number;
  page?: number;
  sortBy?: string;
}

export const createUser = async (userBody: Partial<UserAttributes>) => {
  const existingUser = await User.findOne({ where: { email: userBody.email } });
  if (existingUser) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }
  return User.create(userBody);
};

/**
 * Query for users with pagination
 * @param {Object} filter - Sequelize where conditions
 * @param {Object} options - Query options
 * @param {string} [options.sortBy] - Sort option in the format: sortField:(desc|asc)
 * @param {number} [options.limit] - Maximum number of results per page (default = 10)
 * @param {number} [options.page] - Current page (default = 1)
 */
export const queryUsers = async (
  filter: WhereOptions<UserAttributes>,
  options: PaginationOptions = { page: 1, limit: 10 },
) => {
  const { limit = 10, page = 1, sortBy } = options;
  const offset = (page - 1) * limit;

  let order: any[] = [];
  if (sortBy) {
    const [field, direction] = sortBy.split(':');
    order = [[field, direction.toUpperCase()]];
  }

  const { count, rows: users } = await User.findAndCountAll({
    where: filter,
    limit,
    offset,
    order,
  });

  return {
    results: users,
    page,
    limit,
    totalPages: Math.ceil(count / limit),
    totalResults: count,
  };
};

/**
 * Get user by id
 * @param {number} id
 * @returns {Promise<User>}
 */
export const getUserById = async (id: number) => {
  return User.findByPk(id);
};

/**
 * Get user by email
 * @param {string} email
 * @returns {Promise<User>}
 */
export const getUserByEmail = async (email: string) => {
  return User.findOne({ where: { email } });
};

/**
 * Update user by id
 * @param {number} userId
 * @param {Object} updateBody
 * @returns {Promise<User>}
 */
export const updateUserById = async (userId: number, updateBody: Partial<UserAttributes>) => {
  const user = await getUserById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }

  if (updateBody.email) {
    const existingUser = await User.findOne({
      where: {
        email: updateBody.email,
        id: { [Op.ne]: userId },
      },
    });
    if (existingUser) {
      throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
    }
  }

  Object.assign(user, updateBody);
  await user.save();
  return user;
};

/**
 * Delete user by id
 * @param {number} userId
 * @returns {Promise<User>}
 */
export const deleteUserById = async (userId: number) => {
  const user = await getUserById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  await user.destroy();
  return user;
};

export default {
  createUser,
  queryUsers,
  getUserById,
  getUserByEmail,
  updateUserById,
  deleteUserById,
};
