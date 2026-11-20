import heapq


class RiskPriorityQueue:

    def __init__(self):

        self.queue = []

    def add(self, finding, risk):

        heapq.heappush(
            self.queue,
            (-risk, finding)
        )

    def get_next(self):

        if self.queue:

            return heapq.heappop(self.queue)

        return None