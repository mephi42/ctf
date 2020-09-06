#include <cassert>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <iostream>
#include <map>
#include <vector>

#include "rooms.h"

#define LIBC_CSU_INIT 0xb01130
#define RW_START 0x117f000
#define RW_END 0x1180000
#define AFL_AREA_PTR (RW_START + 0xa0)
#define AFL_PREV_LOC (RW_START + 0xa8)
#define STDOUT (RW_START + 0x20)
#define MAX_AFL_AREA_PTR (LIBC_CSU_INIT + (0x1000 - (LIBC_CSU_INIT & 0xfff)))

struct State {
  std::uint64_t AflAreaPtr;
  std::uint32_t AflPrevLoc;

  bool operator<(const State &Other) const {
    return std::tie(AflAreaPtr, AflPrevLoc) <
           std::tie(Other.AflAreaPtr, Other.AflPrevLoc);
  }

  void Write(std::FILE *File) const {
    std::fwrite(&AflAreaPtr, sizeof(AflAreaPtr), 1, File);
    std::fwrite(&AflPrevLoc, sizeof(AflPrevLoc), 1, File);
  }
};

struct Edge {
  std::uint16_t Room;
  std::uint64_t Addr;
  struct Node *Next;

  void Write(FILE *File) const;
};

struct Node {
  struct State State;
  bool Done;
  std::vector<Edge> Succs;

  void Write(FILE *File) const {
    State.Write(File);
    assert(Succs.size() < 0x10000);
    std::uint16_t SuccCount = Succs.size();
    std::fwrite(&SuccCount, sizeof(SuccCount), 1, File);
    for (const Edge &Succ : Succs)
      Succ.Write(File);
  }
};

void Edge::Write(FILE *File) const {
  std::fwrite(&Room, sizeof(Room), 1, File);
  std::fwrite(&Addr, sizeof(Addr), 1, File);
  Next->State.Write(File);
}

template <typename T> T IncByte(T t, int offset) {
  ((unsigned char *)&t)[offset]++;
  return t;
}

int main() {
  Node *Initial = new Node;
  Initial->State = {0xb01130, 0};
  std::deque<Node *> WorkList = {Initial};
  std::map<State, Node *> Nodes = {{Initial->State, Initial}};
  int iteration = 0;
  while (!WorkList.empty()) {
    iteration++;
    if (iteration % 1000 == 0)
      std::cout << "iteration " << iteration << ", " << Nodes.size() << " nodes"
                << ", " << WorkList.size() << " work items" << std::endl;
    Node *WorkItem = WorkList.front();
    WorkList.pop_front();
    if (WorkItem->Done)
      continue;
    for (size_t i = 0; i < sizeof(rcxes) / sizeof(rcxes[0]); i++) {
      std::uint64_t Addr =
          WorkItem->State.AflAreaPtr + (rcxes[i] ^ WorkItem->State.AflPrevLoc);
      if (Addr < RW_START || Addr >= RW_END)
        continue;
      State NextState = {WorkItem->State.AflAreaPtr, rcxes[i] >> 1};
      if (Addr >= AFL_AREA_PTR && Addr < AFL_AREA_PTR + 8) {
        NextState.AflAreaPtr =
            IncByte(NextState.AflAreaPtr, Addr - AFL_AREA_PTR);
        if (NextState.AflAreaPtr > MAX_AFL_AREA_PTR)
          continue;
      }
      if (Addr >= AFL_PREV_LOC && Addr < AFL_PREV_LOC + 4)
        NextState.AflPrevLoc =
            IncByte(NextState.AflPrevLoc, Addr - AFL_PREV_LOC);
      if (Addr >= STDOUT && Addr < STDOUT + 8)
        continue;
      auto it = Nodes.find(NextState);
      Node *NextNode;
      if (it == Nodes.end()) {
        NextNode = new Node;
        NextNode->State = NextState;
        NextNode->Done = false;
        Nodes[NextNode->State] = NextNode;
        WorkList.push_back(NextNode);
      } else {
        NextNode = it->second;
      }
      assert(i < 0x10000);
      WorkItem->Succs.push_back(Edge{(std::uint16_t)i, Addr, NextNode});
    }
    WorkItem->Done = true;
  }
  FILE *File = std::fopen("graph.bin", "w");
  assert(File != nullptr);
  std::uint32_t NodeCount;
  assert(Nodes.size() < 0x100000000);
  NodeCount = Nodes.size();
  std::fwrite(&NodeCount, sizeof(NodeCount), 1, File);
  for (const auto &Pair : Nodes)
    Pair.second->Write(File);
  std::fclose(File);
}
