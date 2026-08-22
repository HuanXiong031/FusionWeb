import { formatTime } from '../src/lib/utils.ts'

const cases = [
  {
    input: '2026-07-14T14:19:11Z',
    expected: '2026/7/14 22:19:11',
  },
  {
    input: '2026-07-14 22:19:11',
    expected: '2026/7/14 22:19:11',
  },
]

for (const item of cases) {
  const actual = formatTime(item.input)
  if (actual !== item.expected) {
    console.error(`formatTime(${JSON.stringify(item.input)}) = ${JSON.stringify(actual)}, expected ${JSON.stringify(item.expected)}`)
    process.exit(1)
  }
}

console.log('time formatting checks passed')
