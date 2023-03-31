export type Vn = Array<number>;

export const doStuffToMakeTarget = (arr: Vn, target: number) => {
  if (arr.length == target) return arr;
  else if (arr.length < target) return arrPadEnd(arr, target);
  else return arrRemoveEnd(arr, target);
};

export const arrPadEnd = (arr: number[], target: number, pad: number = 0x0) => {
  return [...arr, ...Array(target - arr.length).fill(pad)];
};

export const arrRemoveEnd = (arr: number[], target: number) => {
  return arr.slice(0, target);
};
