import asyncio
from collections import defaultdict

class EventBus:
    def __init__(self): self._s = defaultdict(list)
    def subscribe(self, topic, h): self._s[topic].append(h)
    async def publish(self, topic, event):
        for h in self._s.get(topic, []): asyncio.create_task(h(event))

bus = EventBus()
