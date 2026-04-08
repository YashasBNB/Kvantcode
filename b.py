from alpaca_trade_api.rest import REST, TimeFrame

# --- Replace with your paper trading keys ---
API_KEY = "PKHUE3E5RJWEIBEA5SAOR7JLOA"
API_SECRET = "3jVUKAVeNfDAEjctkxw74VJMDQ6D1Rhx6fwoBkET9P6a"
BASE_URL = "https://paper-api.alpaca.markets"  # Paper trading URL

api = REST(API_KEY, API_SECRET, BASE_URL, api_version='v2')
api = REST(API_KEY, API_SECRET, BASE_URL, api_version='v2')

symbol = "AAPL"
quantity = 10  # number of shares to buy

# --- Optional: Check account buying power ---
account = api.get_account()
print(f"Buying power: ${account.buying_power}")

# --- Place a MARKET order to buy 10 shares ---
order = api.submit_order(
    symbol=symbol,
    qty=quantity,
    side='buy',
    type='market',
    time_in_force='gtc'
)

print("Order placed successfully!")
print(order)
     