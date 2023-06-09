from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import Restaurant, MenuItem
from sqlalchemy import asc, func
from . import db
from flask_login import login_required, current_user

main = Blueprint('main', __name__)

#Show all restaurants
@main.route('/', methods = ['GET', 'POST'])
def showRestaurants():
    if request.method == 'POST':
        query = request.form.get('search_query')
        query = "{}%".format(query)
        #restaurants = db.session.query(Restaurant).filter(func.lower(Restaurant.name) == func.low  er(query))
        restaurants = db.session.query(Restaurant).filter(Restaurant.name.ilike(query)).all()
        return render_template('restaurants.html', restaurants = restaurants)
    
    #Query all restaurants and order them by name in ascending order   
    restaurants = db.session.query(Restaurant).order_by(asc(Restaurant.name))
    return render_template('restaurants.html', restaurants = restaurants)




#Show Profile
@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

#Create a new restaurant
@main.route('/restaurant/new/', methods=['GET','POST'])
@login_required
def newRestaurant():
  #Check user roles to determine access
  if current_user.role != 'administrator' and current_user.role != 'restaurant_owner':
        flash('Access denied. You are not authorized to perform this action.')
        return redirect(url_for('main.showRestaurants'))
  
  #Create a new restaurant with the provided name and owner_id of the creator 
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'], owner_id = current_user.id)
      db.session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      db.session.commit()
      return redirect(url_for('main.showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@main.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
@login_required
def editRestaurant(restaurant_id):
  #Retrieve the restaurant to be edited
  editedRestaurant = db.session.query(Restaurant).filter_by(id = restaurant_id).one()

  #Check user roles to determine access
  if current_user.role != 'administrator' and current_user.role != 'restaurant_owner':
        flash('Access denied. You are not authorized to perform this action.')
        return redirect(url_for('main.showRestaurants'))
  
  if current_user.role == 'restaurant_owner' and current_user.id != editedRestaurant.owner_id:
        flash('Access denied. You are not authorized to edit this restaurant.')
        return redirect(url_for('main.showRestaurants'))
  
  #Edit restaurant based on user input
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('main.showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@main.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
@login_required
def deleteRestaurant(restaurant_id):
  #Retrive the restaurant to be deleted
  restaurantToDelete = db.session.query(Restaurant).filter_by(id = restaurant_id).one()

  #Check user roles to determine access
  if current_user.role != 'administrator' and current_user.role != 'restaurant_owner':
        flash('Access denied. You are not authorized to perform this action.')
        return redirect(url_for('main.showRestaurants'))
  
  if current_user.role == 'restaurant_owner' and current_user.id != restaurantToDelete.owner_id:
        flash('Access denied. You are not authorized to delete this restaurant.')
        return redirect(url_for('main.showRestaurants'))
  
  #Delete restaurant based on user input and commit changes to database
  if request.method == 'POST':
    db.session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    db.session.commit()
    return redirect(url_for('main.showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@main.route('/restaurant/<int:restaurant_id>/')
@main.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    #Retrieve the restaurant and its associated menu items
    restaurant = db.session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = db.session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return render_template('menu.html', items = items, restaurant = restaurant)
     
#Create a new menu item
@main.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
@login_required
def newMenuItem(restaurant_id):
  #Retrieve restaurant details that new menu item will be added to
  restaurant = db.session.query(Restaurant).filter_by(id = restaurant_id).one()
  
  #Check user roles to determine access
  if current_user.role != 'administrator' and current_user.role != 'restaurant_owner':
        flash('Access denied. You are not authorized to perform this action.')
        return redirect(url_for('main.showMenu', restaurant_id=restaurant_id))
  
  if current_user.role == 'restaurant_owner' and restaurant.owner_id != current_user.id:
        flash('Access denied. You are not authorized to edit this menu item.')
        return redirect(url_for('main.showMenu', restaurant_id=restaurant_id))
  
  #Create a new menu item with the provided inputs and restaurant_id
  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id)
      db.session.add(newItem)
      db.session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('main.showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@main.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
@login_required
def editMenuItem(restaurant_id, menu_id):
    #Retrieve menu item and restaurant to be edited
    editedItem = db.session.query(MenuItem).filter_by(id = menu_id).one()
    restaurant = db.session.query(Restaurant).filter_by(id = restaurant_id).one()

    #Check user roles to determine access
    if current_user.role != 'administrator' and current_user.role != 'restaurant_owner':
        flash('Access denied. You are not authorized to perform this action.')
        return redirect(url_for('main.showMenu', restaurant_id=restaurant_id))

    if current_user.role == 'restaurant_owner' and restaurant.owner_id != current_user.id:
        flash('Access denied. You are not authorized to edit this menu item.')
        return redirect(url_for('main.showMenu', restaurant_id=restaurant_id))

    #Edit menu item based on user input
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        db.session.add(editedItem)
        db.session.commit() 
        flash('Menu Item Successfully Edited')
        return redirect(url_for('main.showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)

#Delete a menu item
@main.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
@login_required
def deleteMenuItem(restaurant_id,menu_id):
    #retrieve restaurant and menu item to be deleted
    restaurant = db.session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = db.session.query(MenuItem).filter_by(id = menu_id).one() 

    #Check user roles to determine access
    if current_user.role != 'administrator' and current_user.role != 'restaurant_owner':
        flash('Access denied. You are not authorized to perform this action.')
        return redirect(url_for('main.showMenu', restaurant_id=restaurant_id))

    if current_user.role == 'restaurant_owner' and restaurant.owner_id != current_user.id:
        flash('Access denied. You are not authorized to delete this menu item.')
        return redirect(url_for('main.showMenu', restaurant_id=restaurant_id))

    #Delete menu item and commit changes to the database
    if request.method == 'POST':
        db.session.delete(itemToDelete)
        db.session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('main.showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)
