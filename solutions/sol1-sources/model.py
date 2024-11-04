import torch
import torch.nn as nn


class FFT_LSTMModel(nn.Module):
    def __init__(self, input_size=1, hidden_size=128, output_size=1):
        super(FFT_LSTMModel, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers=1,
                            bidirectional=False, batch_first=True)
        self.fc1 = nn.Linear(hidden_size, hidden_size)
        self.fc2 = nn.Linear(hidden_size, output_size)

    # Takes FFT-ed bitstream as input, and outputs the period

    def forward(self, x):
        _, (hn, _) = self.lstm(x)
        hn = hn.squeeze(0)
        out = self.fc1(hn)
        out = torch.relu(out)
        out = self.fc2(out)
        return out
