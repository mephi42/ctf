#!/usr/bin/env python3
import subprocess

from PIL import Image
import numpy as np


def silly(board):
    board1 = np.zeros(board.shape, dtype=np.uint8)
    for i in range(board.shape[0]):
        for j in range(board.shape[1]):
            il = max(0, i - 1)
            ih = i + 2
            jl = max(0, j - 1)
            jh = j + 2
            n = board[il:ih, jl:jh].sum() - board[i, j]
            if ((board[i, j] == 1 and (n == 2 or n == 3)) or
                    (board[i, j] == 0 and n == 3)):
                board1[i, j] = 1
    return board1


# http://jakevdp.github.io/blog/2013/08/07/conways-game-of-life/
def life_step_2(X):
    """Game of life step using scipy tools"""
    from scipy.signal import convolve2d
    nbrs_count = convolve2d(X, np.ones((3, 3)), mode='same', boundary='wrap') - X
    return (nbrs_count == 3) | (X & (nbrs_count == 2))


def show(board):
    scale = 20
    im = np.zeros((board.shape[0] * scale, board.shape[1] * scale), np.uint8)
    for i in range(board.shape[0]):
        for j in range(board.shape[1]):
            im[i * scale:(i + 1) * scale, j * scale:(j + 1) * scale] = (1 - board[i, j]) * 255
    Image.fromarray(im).save('board.png')
    subprocess.check_call(['display', 'board.png'])


im = Image.open('passphare.png')
board = np.array(im)
board = board.sum(axis=2)  # pixels are either all 0s or all 0xff
board = board[::10, ::10]  # squares are 10x10
board = np.where(board == 0, np.uint8(1), np.uint8(0))  # white = dead, black = alive
board = life_step_2(board)
show(board)  # AJTC8ADEVRA13AR
