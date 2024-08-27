@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        # Receive data from the request's body
        data = request.get_json()
        print(data)

        # Extract the amount in euros
        euro_amount = int(data.get('amount', 0))  # euros

        # Validate the amount
        if euro_amount <= 0:
            return jsonify({'error': 'Invalid amount'}), 400

        # Convert euros to cents
        cent_amount = euro_amount * 100

        # Extract additional fields for Sponsorship
        user_id = data.get('user_id')
        animal_id = data.get('animal_id')
        sponsorship_amount = data.get('sponsorship_amount', '0')  # Default to '0'
        sponsorship_date = data.get('sponsorship_date', datetime.now())  # Default to now

        # Optional: Validate additional fields
        if not user_id or not animal_id:
            return jsonify({'error': 'User ID and Animal ID are required'}), 400

        # Create a checkout session with the specified amount in cents
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': 'Custom Amount',
                    },
                    'unit_amount': cent_amount,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancel',
        )

        # (Optional) Save the sponsorship details in the database
        new_sponsorship = Sponsorship(
            user_id=user_id,
            animal_id=animal_id,
            sponsorship_amount=sponsorship_amount,
            sponsorship_date = data.get('sponsorship_date', None)
        )
        db.session.add(new_sponsorship)
        db.session.commit()

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'url': checkout_session.url})