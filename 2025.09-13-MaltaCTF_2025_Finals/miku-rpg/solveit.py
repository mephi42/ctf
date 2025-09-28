#!/usr/bin/env python3
import random
import socketio
import struct
import networkx
from networkx import single_source_shortest_path_length, shortest_path

DIRECTIONS = {(-1, 0): "left", (1, 0): "right", (0, -1): "up", (0, 1): "down"}


class SDPDeserializer:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_byte(self):
        if self.pos >= len(self.data):
            raise RuntimeError("Unexpected end of data")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n):
        if self.pos + n > len(self.data):
            raise RuntimeError("Unexpected end of data")
        b = self.data[self.pos:self.pos+n]
        self.pos += n
        return b

    def read_varint(self):
        shift = 0
        result = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result

    def read_header(self):
        header = self.read_byte()
        type_id = (header >> 4) & 0x0F
        tag = header & 0x0F
        if type_id > 8:
            raise RuntimeError(f"Invalid type id: {type_id}")
        if tag == 15:
            tag = self.read_varint()
        return type_id, tag

    def read_value(self, type_id):
        if type_id == 0:  # Integer_Positive
            return self.read_varint()
        elif type_id == 1:  # Integer_Negative
            return -self.read_varint()
        elif type_id == 2:  # Float
            return struct.unpack('<f', self.read_bytes(4))[0]
        elif type_id == 3:  # Double
            return struct.unpack('<d', self.read_bytes(8))[0]
        elif type_id == 4:  # String
            length = self.read_varint()
            return self.read_bytes(length).decode('utf-8')
        elif type_id == 5:  # Vector
            length = self.read_varint()
            return [self.read_element() for _ in range(length)]
        elif type_id == 6:  # Map
            length = self.read_varint()
            m = {}
            for _ in range(length):
                key = self.read_element()
                value = self.read_element()
                m[key] = value
            return m
        elif type_id == 7:  # StructBegin
            fields = {}
            while True:
                t, tag = self.read_header()
                if t == 8:  # StructEnd
                    break
                fields[tag] = self.read_value(t)
            return fields
        elif type_id == 8:  # StructEnd (should not be read directly)
            raise RuntimeError("Unexpected StructEnd marker")
        else:
            raise RuntimeError(f"Unsupported type id: {type_id}")

    def read_element(self):
        type_id, tag = self.read_header()
        value = self.read_value(type_id)
        return value


class Board:
    def __init__(self, game_state):
        self.x, self.y = game_state["player"]
        game_data_hex = game_state.get("data")
        if game_data_hex is None:
            self.key_dists = []
            self.collected = 0
        else:
            game_data = SDPDeserializer(bytes.fromhex(game_data_hex)).read_element()
            player = game_data[0]
            assert player == [self.x, self.y]
            name = game_data[1]
            assert name in ("Grass?", "Key"), name
            self.key_dists = game_data[2]
            self.collected = game_data[3]
        print(f"{self.x=} {self.y=}")
        print(f"{self.key_dists=}")
        print(f"{self.collected=}")


class Search:
    def __init__(self, sio):
        self.sio = sio
        self.visited = set()
        self.candidates = None

    def parse_graph(self, game_state):
        bombs = set()
        for bx, by in game_state["bombs"]:
            bombs.add((bx, by))

        self.graph = networkx.Graph()
        for x in range(40):
            for y in range(40):
                if (x, y) in bombs:
                    continue
                if x != 39 and (x + 1, y) not in bombs:
                    self.graph.add_edge((x, y), (x + 1, y))
                if y != 39 and (x, y + 1) not in bombs:
                    self.graph.add_edge((x, y), (x, y + 1))

    def recv_game_state_1(self):
        event = self.sio.receive()
        print(f"{event=}")
        assert event[0] == "game_state"
        game_state = event[1]
        self.board = Board(game_state)
        self.visited.add((self.board.x, self.board.y))
        return game_state

    def recv_game_state(self):
        self.recv_game_state_1()
        self.refine_candidates()

    def move(self, direction):
        print(f"{direction=}")
        self.sio.emit("move", {"direction": direction})
        self.recv_game_state()
        if self.board.key_dists[0] == 0:
            self.sio.emit("pick_key", {"player": [self.board.x, self.board.y]})
            self.recv_game_state()

    def refine_candidates(self):
        candidates = set()

        def add_candidate(x, y):
            if (x, y) in self.graph and (self.candidates is None or (x, y) in self.candidates):
                candidates.add((x, y))

        for dist in self.board.key_dists:
            for dx in range(dist + 1):
                dy = dist - dx
                add_candidate(self.board.x + dx, self.board.y + dy)
                add_candidate(self.board.x - dx, self.board.y + dy)
                add_candidate(self.board.x + dx, self.board.y - dy)
                add_candidate(self.board.x - dx, self.board.y - dy)

        self.candidates = candidates
        print(f"{len(self.candidates)=}")
        print(f"{self.candidates=}")

    def pop_candidate(self):
        dist_candidates = []
        for candidate, dist in single_source_shortest_path_length(self.graph, (self.board.x, self.board.y)).items():
            if candidate in self.candidates:
                dist_candidates.append((dist, candidate))
        dist_candidates.sort()
        print(f"{dist_candidates=}")
        candidate = dist_candidates[0][1]
        self.candidates.remove(candidate)
        return candidate

    def move_to(self, x, y):
        print(f"move_to({x}, {y})")
        path = shortest_path(self.graph, (self.board.x, self.board.y), (x, y))
        print(f"{path=}")
        directions = []
        for i in range(len(path) - 1):
            directions.append(DIRECTIONS[(path[i + 1][0] - path[i][0], path[i + 1][1] - path[i][1])])
        for direction in directions:
            self.move(direction)

def main():
    with socketio.SimpleClient() as sio:
        sio.connect("https://miku-rpg-55029988a1afe204.instancer.challs.mt")

        search = Search(sio)

        # Initial reset - no SDP
        search.sio.emit("reset_game")
        search.parse_graph(search.recv_game_state_1())

        # Move somewhere to receive SDP
        x1, y1 = next(search.graph.neighbors((search.board.x, search.board.y)))
        direction = DIRECTIONS[(x1 - search.board.x, y1 - search.board.y)]
        search.move(direction)

        while True:
            search.move_to(*search.pop_candidate())
        # 'player': [31, 0], 'key_picked': True, 'flag': 'maltactf{m1ku_1n_MALTA??I_4m_Cr4zy_0nc3!!}'


if __name__=="__main__":
    main()
