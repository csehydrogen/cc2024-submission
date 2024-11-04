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


train_dataloader = get_dataloader('train.csv', 128)
val_dataloader = get_dataloader('val.csv', 128)

# Initialize the model
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
model = FFT_LSTMModel()
model = model.to(device)

# Loss and optimizer
criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=0.005,
                       betas=(0.9, 0.999), weight_decay=0.1)
scheduler = optim.lr_scheduler.LambdaLR(optimizer=optimizer,
                                        lr_lambda=lambda epoch: 0.95 ** epoch)


def train_epoch(model, epoch, dataloader, optimizer):
    running_loss = 0.0

    for sequences, periods in dataloader:
        sequences, periods = sequences.to(device), periods.to(device)
        optimizer.zero_grad()
        outputs = model(sequences)
        loss = criterion(outputs.squeeze(), periods)
        loss.backward()
        optimizer.step()
        running_loss += loss.item()

    return running_loss / len(dataloader)


def test(model, dataloader):
    correct = 0
    for sequences, periods in dataloader:
        sequences, periods = sequences.to(device), periods.to(device)
        outputs = model(sequences)
        outputs = torch.round(outputs)
        correct += (outputs.squeeze() == periods).sum().item()
    return correct / len(dataloader.dataset)


# print csv header
print("epoch,train_loss,val_acc")
best_model, best_val_acc = None, -1.0
NUM_EPOCHS = 100
for epoch in range(NUM_EPOCHS):
    train_loss = train_epoch(
        model, epoch, train_dataloader, optimizer=optimizer)
    val_acc = test(model, val_dataloader)
    print(f"{epoch},{train_loss},{val_acc}")

    if val_acc > best_val_acc:
        best_val_acc = val_acc
        best_model = copy.deepcopy(model)

    scheduler.step()

print(f"Training done")
print(f"Best validation accuracy: {best_val_acc*100:.2f}%")
torch.save(best_model.state_dict(), "model.pth")
