import torch
import torch.nn as nn

class BasicBlock(nn.Module):
  def __init__(self, c, k):
    super().__init__()
    self.fc1 = nn.Linear(c, k, bias=False)
    self.bn1 = nn.LayerNorm(k)
    self.fc2 = nn.Linear(k, k, bias=False)
    self.bn2 = nn.LayerNorm(k)
    self.relu = nn.ReLU(inplace=True)
    self.downsample = None
    if c != k:
      self.downsample = nn.Sequential(
        nn.Linear(c, k, bias=False),
        nn.LayerNorm(k)
      )
  def forward(self, x):
    identity = x
    x = self.fc1(x)
    x = self.bn1(x)
    x = self.relu(x)
    x = self.fc2(x)
    x = self.bn2(x)
    if self.downsample is not None:
      identity = self.downsample(identity)
    x += identity
    x = self.relu(x)
    
    return x

class MyModel(nn.Module):
  def __init__(self, W):
    super().__init__()
    self.conv1 = BasicBlock(W, 64)
    self.conv2 = nn.Sequential(
      BasicBlock(64, 64),
      BasicBlock(64, 64)
    )
    self.conv3 = nn.Sequential(
      BasicBlock(64, 128),
      BasicBlock(128, 128)
    )
    self.conv4 = nn.Sequential(
      BasicBlock(128, 256),
      BasicBlock(256, 256)
    )
    self.fc = nn.Linear(256, 2)

    for m in self.modules():
      if isinstance(m, nn.Linear):
        nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
      elif isinstance(m, nn.LayerNorm):
        nn.init.constant_(m.weight, 1)
        nn.init.constant_(m.bias, 0)

  def forward(self, x):
    x = self.conv1(x)
    x = self.conv2(x)
    x = self.conv3(x)
    x = self.conv4(x)
    x = self.fc(x)
    return x

class XorModel(nn.Module):
  def __init__(self, W):
    super().__init__()

  def forward(self, x):
    x = x.sum(1) % 2
    x = torch.stack([1 - x, x], 1)
    return x