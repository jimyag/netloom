import { apiClient } from "./client";

export type Item = {
  description: string;
  id: string;
  name: string;
};

export async function getItems(signal?: AbortSignal) {
  const response = await apiClient.get<Item[]>("/items", { signal });
  return response.data;
}

export async function getItem(id: string, signal?: AbortSignal) {
  const response = await apiClient.get<Item>(`/items/${id}`, { signal });
  return response.data;
}
