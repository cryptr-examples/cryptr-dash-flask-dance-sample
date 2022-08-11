# Run this app with `python app.py` and
# visit http://127.0.0.1:8050/ in your web browser.

from dash import Dash, dcc, html, Output, Input, State
import plotly.express as px
import pandas as pd

app = Dash(__name__)

# assume you have a "long-form" data frame
# see https://plotly.com/python/px-arguments/ for more options
df = pd.DataFrame({
    "Fruit": ["Apples", "Oranges", "Bananas", "Apples", "Oranges", "Bananas"],
    "Amount": [4, 1, 2, 2, 4, 5],
    "City": ["SF", "SF", "SF", "Montreal", "Montreal", "Montreal"]
})

fig = px.bar(df, x="Fruit", y="Amount", color="City", barmode="group")

app.layout = html.Div(children=[
    html.H1(children='Hello Dash'),
    html.Div(dcc.Input(id='input-on-submit', type='text')),
    html.Button('Submit', id='submit-val', n_clicks=0),
    html.Div(id='container-button-basic',
             children='Enter a value and press submit'),

    html.Div(children='''
        Dash: A web application framework for your data.
    '''),


    dcc.Graph(
        id='example-graph',
        figure=fig
    )
])

@app.callback(
  Output('container-button-basic', 'children'),
  Input('submit-val', 'n_clicks'),
  State('input-on-submit', 'value'),
)

def update_output(n_clicks, value):
  return 'The input value was "{}" and the button has been clicked {} times'.format(
    value,
    n_clicks
  )

if __name__ == '__main__':
    app.run_server(debug=True)
