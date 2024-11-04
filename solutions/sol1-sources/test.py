import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
import torch.nn as nn
import torch.optim as optim
import copy
from model import FFT_LSTMModel


class SequenceDataset(Dataset):
    def __init__(self, sequences, targets):
        self.sequences = sequences
        self.targets = targets

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        sequence = torch.tensor(self.sequences[idx], dtype=torch.float)
        period = torch.tensor(self.targets[idx], dtype=torch.float)
        return sequence, period


def collate_fn(data):
    x_fft = [torch.abs(torch.fft.fft(d[0])).unsqueeze(-1) for d in data]
    y = [d[1] for d in data]
    x_fft_packed = torch.nn.utils.rnn.pack_sequence(
        x_fft, enforce_sorted=False)
    return x_fft_packed, torch.tensor(y, dtype=torch.float)


def get_dataloader(fname, batch_size):
    df = pd.read_csv(fname)
    df['seq'] = df['seq'].apply(lambda x: [int(char) for char in x])
    X = df['seq'].tolist()
    y = df['period'].values
    return DataLoader(SequenceDataset(X, y), batch_size=batch_size, shuffle=True, collate_fn=collate_fn)


test_dataloader = get_dataloader('test.csv', 128)

# Initialize the model
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
model = FFT_LSTMModel()
model = model.to(device)


def test(model, dataloader):
    correct = 0
    for sequences, periods in dataloader:
        sequences, periods = sequences.to(device), periods.to(device)
        outputs = model(sequences)
        outputs = torch.round(outputs)
        correct += (outputs.squeeze() == periods).sum().item()
    return correct / len(dataloader.dataset), correct, len(dataloader.dataset)


# Test
model.load_state_dict(torch.load('model.pth'))
model.eval()
acc, correct, total = test(model, test_dataloader)
print(f"Test accuracy: {acc*100: .2f} %, {correct} / {total}")
