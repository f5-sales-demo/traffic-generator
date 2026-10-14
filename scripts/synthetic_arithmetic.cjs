// Parse the lab's arithmetic captcha without evaluating JavaScript.
function syntheticArithmetic(expression) {
  if (!/^\d+(?:[+*-]\d+){1,2}$/.test(expression)) throw new Error('Unexpected synthetic arithmetic');
  const terms = expression.split(/([+-])/);
  const product = (text) =>
    text
      .split('*')
      .map(Number)
      .reduce((value, term) => value * term, 1);
  let answer = product(terms[0]);
  for (let index = 1; index < terms.length; index += 2)
    answer += (terms[index] === '+' ? 1 : -1) * product(terms[index + 1]);
  return answer;
}
module.exports = { syntheticArithmetic };
