from collections import deque


def bfs(graph, start, target):

    queue = deque([[start]])

    visited = set()

    while queue:

        path = queue.popleft()

        node = path[-1]

        if node == target:

            return path

        if node in visited:

            continue

        visited.add(node)

        for neighbour in graph.get_neighbors(node):

            new_path = path + [neighbour]

            queue.append(new_path)

    return None
