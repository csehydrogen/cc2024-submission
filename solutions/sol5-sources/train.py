import torch
import torch.nn as nn
from torch import Tensor
from typing import Any, Callable, List, Optional, Type, Union
from model import MyModel
from util import load_helper
import argparse

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('--round', type=int, default=4, choices=[4, 5])
  parser.add_argument('--seed', type=int, default=42)
  parser.add_argument('--model', type=str, default='ours', choices=['hou', 'ours'])
  args = parser.parse_args()
  helper = load_helper()
  helper.set_seed(args.seed)

  # constants
  nepoch = 200
  train_dataset_sz = 100000
  test_dataset_sz = 10000
  max_bsz = 1000
  best_acc = 0.0
  best_model = None
  target_round = args.round
  model_input_size = helper.get_model_input_size(target_round)
  hou_style = args.model == 'hou'

  # generate dataset
  X_train = torch.empty([train_dataset_sz, model_input_size], dtype=torch.float32)
  Y_train = torch.empty([train_dataset_sz], dtype=torch.long)
  X_test = torch.empty([test_dataset_sz, model_input_size], dtype=torch.float32)
  Y_test = torch.empty([test_dataset_sz], dtype=torch.long)
  helper.gen_dataset(train_dataset_sz, X_train, Y_train, target_round, hou_style)
  helper.gen_dataset(test_dataset_sz, X_test, Y_test, target_round, hou_style)

  # model train
  model = MyModel(model_input_size).cuda()
  criterion = nn.CrossEntropyLoss()
  optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
  for epoch in range(nepoch):
    model.train()
    for data_idx in range(0, train_dataset_sz, max_bsz):
      if train_dataset_sz - data_idx < max_bsz:
        continue
      x = X_train[data_idx:data_idx+max_bsz].cuda()
      y = Y_train[data_idx:data_idx+max_bsz].cuda()
      optimizer.zero_grad()
      output = model(x)
      loss = criterion(output, y)
      loss.backward()
      optimizer.step()
    model.eval()
    correct = 0
    for data_idx in range(0, test_dataset_sz, max_bsz):
      x = X_test[data_idx:data_idx+max_bsz].cuda()
      y = Y_test[data_idx:data_idx+max_bsz].cuda()
      output = model(x)
      score = torch.argmax(output, dim=1) == y
      correct += score.sum().item()
    acc = correct / test_dataset_sz
    print(f'epoch: {epoch}, accuracy: {acc}, ({correct} / {test_dataset_sz})')
    if best_acc < acc:
      best_acc = acc
      best_model = model.state_dict()
  fn = f'model_{args.model}_round_{target_round}.pt'
  print(f'best accuracy: {best_acc}, Saving to {fn}...')
  torch.save(best_model, fn)

