import httpStatus from 'http-status';
import { ApiError, pick, catchAsync } from '../utils';
import { userService } from '../services';
import { Request, Response } from 'express';

export const createUser = catchAsync(async (req: Request, res: Response) => {
  const user = await userService.createUser(req.body);
  res.status(httpStatus.CREATED).send(user);
});

export const getUsers = catchAsync(async (req: Request, res: Response) => {
  const filter = pick(req.query, ['name', 'role']);
  const options = pick(req.query, ['sortBy', 'limit', 'page']);
  const result = await userService.queryUsers(filter, options);
  res.send(result);
});

type ReqParams = { userId?: string };
type ReqBody = {};
type ReqQuery = {};
type ResBody = {};
type TRequestUserId = Request<ReqParams, ResBody, ReqBody, ReqQuery>;

export const getUser = catchAsync(async (req: TRequestUserId, res: Response) => {
  if (req?.params?.userId) {
    const user = await userService.getUserById(parseInt(req.params.userId));
    if (!user) {
      throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
    }
    res.send(user);
  } else {
    throw new ApiError(httpStatus.NOT_FOUND, 'User Id not found');
  }
});

export const updateUser = catchAsync(async (req: TRequestUserId, res: Response) => {
  if (req?.params?.userId) {
    const user = await userService.updateUserById(parseInt(req.params.userId), req.body);
    res.send(user);
  } else {
    throw new ApiError(httpStatus.NOT_FOUND, 'User Id not found');
  }
});

export const deleteUser = catchAsync(async (req: TRequestUserId, res: Response) => {
  if (req.params.userId) {
    await userService.deleteUserById(parseInt(req.params.userId));
    res.status(httpStatus.NO_CONTENT).send();
  } else {
    throw new ApiError(httpStatus.NOT_FOUND, 'User Id not found');
  }
});

export default {
  createUser,
  getUsers,
  getUser,
  updateUser,
  deleteUser,
};
