from model import MyModel, XorModel
from util import load_helper
import random
import torch
import argparse

def gen_random_key():
  return random.randrange(2 ** 64)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('--round', type=int, default=4, choices=[4, 5])
  parser.add_argument('--seed', type=int, default=42)
  parser.add_argument('--model', type=str, default='ours', choices=['xor', 'hou', 'ours'])
  parser.add_argument('--npair', type=int, required=True)
  parser.add_argument('--niter', type=int, default=1)
  args = parser.parse_args()
  helper = load_helper()
  helper.set_seed(args.seed)
  random.seed(args.seed)

  target_round = args.round
  model_input_size = helper.get_model_input_size(target_round)

  # now we generate key candidates
  key_cand = []
  helper.gen_key_cand_as_intdiff(key_cand, target_round)
  ncand = len(key_cand)
  mask = key_cand[-1]

  print('Loading model...')
  if args.model == 'xor':
    model = XorModel(model_input_size).cuda()
  else:
    fn = f'model_{args.model}_round_{target_round}.pt'
    model = MyModel(model_input_size).cuda()
    model.load_state_dict(torch.load(fn, weights_only=True))
  model.eval()

  avg_rank = 0
  for iter in range(args.niter):
    # generate 8B key. model knows nothing about this key
    key = gen_random_key()
    rhs_xor = helper.check_rhs(key, target_round)

    #print('Generating pairs...')
    npair = args.npair
    pts, cts = [], []
    helper.gen_pair_with_key(npair, pts, cts, key, target_round)

    # generate model input (11bit)
    #print('Generating inputs...')
    lhs = torch.empty([npair, len(key_cand), model_input_size], dtype=torch.float32)
    helper.extract_lhs(npair, pts, cts, key_cand, lhs, target_round)

    total_score = torch.zeros([len(key_cand)], dtype=torch.long).cuda()
    #print('Starting inference...')
    for i in range(npair):
      input = lhs[i].cuda()
      output = model(input)
      score = (torch.argmax(output, dim=1) == 1).long()
      total_score += score

    # check answer
    for i in range(ncand):
      if key & mask == key_cand[i]:
        ans_idx = i
        break

    #real_score = torch.abs(total_score.cpu() - torch.full([ncand], npair / 2))

    rank = torch.where(torch.argsort(total_score) == ans_idx)[0].item()
    rank = ncand / 2 - abs(rank - ncand / 2)
    avg_rank += rank
    print(f'Iter {iter}: rank {rank}')
  print(f'Avg rank: {avg_rank / args.niter}')